# Hidden (password-protected) photos — design spec

Date: 2026-09-22
Status: Approved design, pending implementation plan

## Goal

Let the user hide a photo or a selection of photos from every app view. Hidden
photos can be revealed per-album via a toolbar toggle, which requires an OS-level
authentication (Touch ID / Windows Hello) or an app PIN fallback, once per app
session.

Explicitly NOT a goal: encrypting file bytes on disk. Files remain readable by
any tool outside the app. This matches Apple Photos' "Hidden" album model: it
protects against casual browsing inside the app, not against filesystem access.

## Performance requirement

No measurable performance regression is allowed. The design achieves this by
making hiding a single extra indexed `WHERE` predicate on queries that already
apply several such predicates, and by keeping all unlock state in memory.

## Decisions (confirmed with user)

| Decision | Choice |
|---|---|
| Security model | DB flag + OS-auth gate; no file encryption |
| Where hidden photos appear | Per-album toolbar toggle in the grid (not a dedicated sidebar view) |
| Platforms | All: macOS LocalAuthentication, Windows Hello, app-PIN fallback (Linux + unavailable OS auth) |
| Schema versioning | Fire-and-forget `ALTER` in `create_db_internal` — NO numbered migration (avoids `user_version` collisions with upstream) |
| Coexistence | Fork and official app must be able to alternate on the same library DB without breaking each other |

## Architecture

### 1. Schema (`src-tauri/src/t_sqlite.rs`)

- Add `is_hidden INTEGER NOT NULL DEFAULT 0` to the `CREATE TABLE afiles` statement
  so fresh databases get it directly.
- In `create_db_internal`, next to the existing `has_faces`/`rating`/`culling_flag`
  fire-and-forget ALTERs (~line 9615), add:
  - `let _ = conn.execute("ALTER TABLE afiles ADD COLUMN is_hidden INTEGER NOT NULL DEFAULT 0", []);`
  - `conn.execute("CREATE INDEX IF NOT EXISTS idx_afiles_is_hidden ON afiles(is_hidden)", [])`
- Rationale: `check_and_migrate` is strictly linear (`version > user_version`). A
  fork-registered numbered migration would collide with upstream's future
  same-numbered migration and cause it to be silently skipped. The unversioned
  ALTER block has no such hazard and matches upstream's own convention.
- `AFile` struct gets `is_hidden: bool` (or `Option<bool>` matching sibling flags);
  include it in the file-info SELECT/row-mapping used by `get_file_info` AND in
  the file-list SELECT/row-mapping (~line 3129, the `a.is_favorite, a.rating, ...`
  column list) — the frontend needs `f.is_hidden` for menu labels and the
  thumbnail badge.
- IMPORTANT for coexistence: do NOT add `is_hidden` to `AFile::update`'s explicit
  column list (~line 2933) and do NOT write it from `update_file_info`. The flag
  is written exclusively by `set_files_hidden`. This mirrors how `is_favorite`
  already survives refreshes, and guarantees refresh/scan/move paths in BOTH the
  fork and the official build preserve the flag (see Coexistence section).

### 2. Query filtering

- New helper `AFile::hidden_exclusion_condition(alias)` returning
  `COALESCE(<alias>.is_hidden, 0) = 0` — same pattern as
  `search_exclusion_condition`.
- `QueryParams` gains `include_hidden: bool` (default false). In
  `build_search_query_parts`, the hidden condition is pushed when
  `!params.include_hidden`. This covers the main grid for albums, smart albums,
  collections, tag/person/search panes — wherever the toolbar toggle applies.
- Unconditional hiding (no toggle, `include_hidden` not honored) at every other
  `afiles` query site. Audit list — every place `search_exclusion_condition` or a
  raw `FROM afiles`/`JOIN afiles` appears must gain the hidden predicate:
  - Calendar/date counts (the big SUM query ~line 2131)
  - Map clusters / geotag queries
  - Persons/faces queries and person thumbnail selection
  - Camera/lens/location facet lists (~lines 8987, 9065, 9145)
  - Collections listing (`acollections_files` joins)
  - Dedup results, similarity results, "find similar", "find person" result sets
  - Album/folder file counts and status-bar totals
  - Any grouped-view queries (grouped timeline/grouped rows in Content.vue are
    fed by these same backend calls)
- Effect: hidden files never appear in Map, People, Dedup, calendar histograms,
  or facet counts — even when unlocked. The toggle affects only the current
  grid's file list.

### 3. Commands (`t_cmds.rs`) + capabilities

- `set_files_hidden(file_ids: Vec<i64>, hidden: bool)` → single transaction
  `UPDATE afiles SET is_hidden = ? WHERE id IN (...)`; returns updated count.
  Reuse the existing post-update refresh mechanism used by
  `set_file_culling_flag` (event emission → grid re-query).
- `unlock_hidden()` → `Result<bool, String>` — runs the platform auth.
- `lock_hidden()` → clears session unlock.
- `hidden_unlock_state()` → `bool` — for UI to render the toggle correctly
  (e.g., after window switch).
- `hidden_pin_status()` → `bool` — whether an app PIN exists (decides between
  "enter PIN" and "create PIN" dialog modes).
- `set_hidden_pin(pin)` / `verify_hidden_pin(pin)` — salted iterated SHA-256
  (e.g. 100k iterations, 16-byte random salt via `rand`), stored in a fork-only
  file (`hidden_pin.json`) in the app config dir — NOT inside the shared
  config.json, so an official build can never choke on unknown config keys.
  `sha2` and `rand` are already deps.
- Register all new commands in `src-tauri/capabilities/*.json`.

### 4. Unlock state

- `static HIDDEN_UNLOCKED: AtomicBool` (or `OnceCell<RwLock>`) in Rust — in-memory
  only, never persisted. App restart = locked. Locking is global across all
  windows; the reveal toggle is per-window UI state.

### 5. Platform auth (`src-tauri/src/t_auth.rs`, new file)

- `unlock_hidden()` dispatches per-OS:
  - **macOS**: `LAContext.evaluatePolicy(LAPolicy::deviceOwnerAuthentication)`
    — Touch ID with automatic system-password fallback. Implement as a small
    `LocalAuth.mm` Objective-C shim next to `pasteboard.mm`, compiled via the
    existing `build.rs` cc setup (precedent already in tree; avoids betting on
    `objc2-local-authentication` crate compatibility — can revisit later).
    If `canEvaluatePolicy` fails → return a sentinel so the frontend falls back
    to the PIN dialog.
  - **Windows**: `Windows.Security.Credentials.UI.UserConsentVerifier`
    (Windows Hello face/fingerprint/PIN). New dep:
    `windows` crate with features `["Security_Credentials_UI", "Foundation"]`
    (pin the latest stable version at implementation time).
    `CheckAvailabilityAsync` → if unavailable → PIN fallback.
  - **Linux**: no OS biometric → straight to app PIN.
- All OS-auth calls must run off the UI thread / via `tauri::async_runtime`
  (they show OS modal dialogs and can take seconds).

### 6. Media-serving gates (`t_protocol.rs`, `t_http.rs`)

- `thumb://` handler: after parsing `file_id`, check
  `is_hidden && !HIDDEN_UNLOCKED` → 404. One indexed row read per request on a
  path that already queries the DB per request — negligible.
- `preview://` handler: same check (file info is already fetched there — just
  read `is_hidden` off it).
- Linux video HTTP server (`t_http.rs`): resolve `path` → `afiles` row; same gate.
- `asset://` (Tauri built-in, used by `convertFileSrc`/`getAssetSrc` for
  full-res in the viewer): cannot be intercepted. Acceptable under the stated
  security model — the frontend never renders hidden files, and the files are
  readable on disk anyway. Add a code comment noting this boundary.

### 7. Frontend

**Context menu** (`src-vite/src/common/fileMenu.ts`):

- `buildSingleFileMenu`: new item directly below the "Set as" submenu:
  `{ label: f.is_hidden ? t('unhide') : t('hide'), icon: f.is_hidden ? IconEye : IconEyeOff, action: 'hide' | 'unhide' }`.
- `buildSelectionMenu`: same item acting on the whole selection (label from the
  majority/first item's state — spec: if any selected file is not hidden →
  "Hide"; else "Unhide").

**Action dispatch** (`Content.vue::handleItemAction`):

- `'hide'`: single → `set_files_hidden([file.id], true)`; select mode → all
  selected ids. Then drop hidden ids from selection (they leave the list).
- `'unhide'`: only reachable while `showHidden` is on (files aren't visible
  otherwise) → `set_files_hidden(ids, false)`.
- Both reuse the existing refresh path so counts/status bar update.

**Toolbar toggle** (`Content.vue` toolbar cluster, ~lines 100–170):

- Eye/eye-off `PanelActionButton` to the right of the existing buttons.
- Click while `!unlocked` → call `unlock_hidden()` → on success
  `showHidden = true`, set `include_hidden=1` in the query params, re-query.
  On cancel/failure → no state change (silent, OS dialog already communicated).
- Click while unlocked → flip `showHidden`, re-query.
- `showHidden` resets to `false` whenever the query source changes (different
  album/folder/collection/search) — watch the same reactive deps that trigger
  `clearSelectionForFileListUpdate`/reloads.
- While `showHidden` is on, hidden thumbnails get a small eye-off badge overlay
  in `Thumbnail.vue` so they're distinguishable inline.

**PIN dialog** (`UnlockHiddenDialog.vue`, new, reusing `ModalDialog.vue`):

- Modes: `verify` (enter PIN) and `create` (first-time set + confirm).
- Used on Linux always, and on macOS/Windows when OS auth is unavailable.

**Viewer edge cases**:

- ImageViewer/filmstrip navigate `fileList`, so hidden items only exist in the
  nav while `showHidden` is on. If the user toggles hidden off (or locks) while
  viewing a hidden photo, the list shrinks — the viewer already handles
  `removeDeletedFilesFromImageViewerSession`-style shrinkage; reuse that path.
- Slideshow, hover preview, compare windows inherit behavior from the file list
  — no special casing needed.

**i18n**: new keys in every file under `src-vite/src/locales`:
`menu.file.hide`, `menu.file.unhide`,
`toolbar.tooltip.show_hidden`, `hidden.unlock_title`,
`hidden.pin_create`, `hidden.pin_enter`, `hidden.pin_wrong`.

## Error handling

- `set_files_hidden` failures → existing toast error path.
- OS auth errors other than user-cancel → log + toast; user-cancel → silent.
- Wrong PIN → inline error in dialog, no lockout policy in v1 (YAGNI; the PIN
  gates UI only).
- Locked + hidden `file_id` requested via protocols → 404, same as missing file
  (deliberately indistinguishable).

## Testing

- Rust unit tests alongside existing ones in `t_sqlite.rs` test module:
  - hidden rows excluded from `build_search_query_parts` output when
    `include_hidden=false`, included when true
  - `set_files_hidden` updates flag idempotently
  - conditional-on-album visibility: hidden file in album A invisible in album B
    queries
- Manual verification matrix: hide single/multi, reveal per album, restart app
  (re-locks), map/people/dedup absence, protocol 404 while locked, viewer
  navigation across a toggle-off.
- Coexistence matrix: hide in fork → open official build (files visible, app
  works, refresh/scan/folder-move in official) → reopen fork (flags intact,
  still hidden); upstream migration simulation unaffected.

## Coexistence with the official app

Requirement: the user can alternate between this fork and the official build on
the same library database with everything working in both.

Guaranteed by design:

- `is_hidden` column + index are invisible to the official build (SQLite ignores
  unknown columns); `user_version` is never touched, so official migrations
  apply normally in both directions.
- `is_hidden` survives every official write path, verified against the code:
  - `AFile::update` (refresh file info) writes an explicit column list that
    doesn't mention the flag → preserved.
  - Scans insert via `INSERT ... ON CONFLICT(folder_id, name) DO NOTHING` →
    existing rows untouched.
  - Folder moves rewrite `afolders.path` only; `afiles` rows keep their
    `folder_id` → preserved. (The `DELETE FROM afiles WHERE folder_id` calls at
    ~1138/1183/1233 are destination cleanup or folder deletion — files being
    deleted/overwritten SHOULD lose hidden state.)
  - Net: `is_hidden` has exactly the same durability guarantees as
    `is_favorite`/`rating` under both builds.
- PIN data lives in `hidden_pin.json` — a file the official build never reads.

Accepted limitations (document in README/PR notes):

- Hidden photos are VISIBLE in the official build — it has no concept of the
  flag. Expected under the non-encryption model.
- Copying a folder containing hidden photos produces unhidden copies (new rows,
  `is_hidden=0`), same as favorites not propagating to copies.
- Do not run both builds simultaneously on the same library — alternating
  launches are fine; concurrent writers are untested.
- If the user ever switches to the official build permanently, hidden files are
  just normal files again — no data cleanup needed.

## Out of scope (YAGNI)

- File encryption, hidden albums as a sidebar destination, auto-relock timers,
  per-library PINs, hidden folders, decoy/duress PINs, hiding from OS-level
  caches (webview image cache may retain thumbnails for the session —
  acknowledged, acceptable).

## Implementation order

1. `is_hidden` column (CREATE TABLE + fire-and-forget ALTER + index) + `AFile` field
2. `hidden_exclusion_condition` + `include_hidden` param + full query-site audit
3. `set_files_hidden` command + context-menu items + dispatch + i18n keys
4. `HIDDEN_UNLOCKED` state + `t_auth.rs` macOS LocalAuthentication shim
5. Toolbar toggle + `include_hidden` plumbing + thumbnail badge
6. Windows Hello + app-PIN storage + `UnlockHiddenDialog`
7. Protocol gates (thumb/preview/Linux video server) + final leak-path audit
