# Hidden Photos Implementation Plan

> **For agentic workers:** Implements `docs/superpowers/specs/2026-09-22-hidden-photos-design.md`. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hide photos from all app views behind a per-album, OS-auth-gated reveal toggle, with no perf regression and full coexistence with the official build.

**Architecture:** `afiles.is_hidden` flag (added via fire-and-forget `ALTER`, NOT a numbered migration), global `WHERE` exclusion on every `afiles` query, session-scoped unlock in Rust (`AtomicBool`), platform auth (macOS `LocalAuthentication` / Windows Hello / app-PIN fallback), `thumb://`+`preview://` protocol gate.

**Tech Stack:** Rust/Tauri 2, rusqlite, Vue 3, Objective-C shim (existing `cc` build), `sha2`/`rand` (existing deps), `windows` crate (new, cfg-gated).

## Global Constraints

- NEVER touch `PRAGMA user_version` or `t_migration.rs` — schema change goes in `create_db_internal`'s fire-and-forget ALTER block only.
- NEVER add `is_hidden` to `AFile::update`'s column list or `update_file_info` — flag written only by `set_files_hidden`.
- Hidden files excluded from EVERY query except the main grid when `include_hidden=true`. Map/People/Dedup/calendar/facets/collections counts always exclude.
- Unlock state in-memory only (`AtomicBool`); never persisted.
- PIN stored in `hidden_pin.json` (fork-only file), salted iterated SHA-256 — never in shared `app-config.json`.
- Follow existing code patterns (per CONTRIBUTING.md: performance first, small focused diffs).

---

### Task 1: `is_hidden` column + query filtering + `set_files_hidden` (Rust)

**Files:**
- Modify: `src-tauri/src/t_sqlite.rs` (schema ~9510, ALTER block ~9615, `AFile` struct ~1450, `get_file_info` SELECT ~3129, `QueryParams` ~1950, `SmartQueryParams` ~2010, `build_search_query_parts` ~4600, helper near `search_exclusion_condition` ~2147)
- Modify: `src-tauri/src/t_cmds.rs` (near `set_file_culling_flag` ~2851, `BatchFileMetadataUpdate` ~2859, command registration in `main.rs` invoke_handler list)

**Interfaces:**
- Produces: `AFile::is_hidden: Option<bool>`; `QueryParams.include_hidden: bool` (`#[serde(default)]`); `SmartQueryParams.include_hidden: bool`; `AFile::hidden_exclusion_condition(alias: &str) -> String` = `COALESCE(<alias>.is_hidden,0) = 0`; command `set_files_hidden(file_ids: Vec<i64>, hidden: bool) -> Result<usize,String>`.

- [ ] **Step 1:** Add `is_hidden INTEGER NOT NULL DEFAULT 0` to `CREATE TABLE afiles`; add `let _ = conn.execute("ALTER TABLE afiles ADD COLUMN is_hidden INTEGER NOT NULL DEFAULT 0", []);` and `CREATE INDEX IF NOT EXISTS idx_afiles_is_hidden ON afiles(is_hidden)` in the ALTER block (~line 9624, after `culling_flag` ALTER).

- [ ] **Step 2:** Add `pub is_hidden: Option<bool>` to `AFile` struct (near `is_favorite` ~1450), `#[serde(rename_all = "camelCase")]` already covers it → `isHidden` in JSON. Include `a.is_hidden` in the file-list SELECT column list (~3129) + row mapping, and in `get_file_info`'s SELECT/mapping. Check every `row.get(N)` index stays aligned.

- [ ] **Step 3:** Add `fn hidden_exclusion_condition(alias) -> String` next to `search_exclusion_condition` (~2147). In `build_search_query_parts` (~4606, after `is_favorite` block): `if !params.include_hidden { conditions.push(Self::hidden_exclusion_condition("a")) }`. Add `include_hidden` field (serde default false) to `QueryParams` and `SmartQueryParams`; apply same conditional in the smart-query builder.

- [ ] **Step 4:** Audit unconditional hiding — grep `FROM afiles`/`JOIN afiles`/`search_exclusion_condition` sites (~2131 calendar counts, ~4471/4498, ~5723, ~6412, ~7803-7868, ~8273, ~8913-9145 facet lists, persons, dedup, collections joins, `get_files_by_ids`?, map clusters). Add `AND COALESCE(a.is_hidden,0)=0` (matching alias) to each — EXCEPT the main `build_search_query_parts` (conditional) and `get_file_info`/`get_files_by_ids` (single-row lookups must still resolve so protocol gate + viewer can check the flag).

- [ ] **Step 5:** `set_files_hidden(file_ids: Vec<i64>, hidden: bool)` in `t_cmds.rs`: `UPDATE afiles SET is_hidden=?1 WHERE id IN (...)` in one transaction, chunk ids to SQLite's 999-param limit; return affected count. Also add `is_hidden: Option<bool>` to `BatchFileMetadataUpdate` for parity. Register in `main.rs` invoke_handler.

- [ ] **Step 6:** Unit test in the `tag_group_query_tests`-style test module at file bottom: in-memory conn with minimal schema + 1 hidden / 1 visible row → `build_search_query_parts` WHERE contains `is_hidden` only when `include_hidden=false`; verify row counts via a count query.

- [ ] **Step 7:** `cd src-tauri && cargo test hidden` + `cargo check`. Commit `feat(hidden): is_hidden flag, query filtering, set_files_hidden`.

### Task 2: `t_auth.rs` — unlock state + platform auth + PIN (Rust)

**Files:**
- Create: `src-tauri/src/t_auth.rs`, `src-tauri/src/LocalAuth.mm` (macOS)
- Modify: `src-tauri/src/main.rs` (mod + commands), `src-tauri/build.rs` (compile LocalAuth.mm in the existing macOS cc block), `src-tauri/Cargo.toml` (`windows` dep, cfg-gated)

**Interfaces:**
- Produces commands: `unlock_hidden() -> String` (`"ok"`|`"cancelled"`|`"unavailable"`), `lock_hidden()`, `hidden_unlock_state() -> bool`, `hidden_pin_status() -> bool`, `set_hidden_pin(pin: String)`, `verify_hidden_pin(pin: String) -> bool`.

- [ ] **Step 1:** `static HIDDEN_UNLOCKED: AtomicBool`; `pub fn hidden_unlocked() -> bool`, `pub(crate) fn set_unlocked(bool)` — used by protocol gate (Task 5).

- [ ] **Step 2:** `LocalAuth.mm`: `extern "C" int lap_auth_unlock(void)` → `LAContext`, `evaluatePolicy:LAPolicyDeviceOwnerAuthentication` synchronously (semaphore), return 0 ok / 1 cancelled / 2 unavailable; call inside `dispatch_sync(dispatch_get_main_queue(), ...)` if LA requires — verify: `evaluatePolicy` may be called off-main, keep simple sync call on a spawned thread. Register in build.rs macOS block next to `pasteboard.mm`, `extern "C" { fn lap_auth_unlock() -> i32; }` in t_auth.rs behind `#[cfg(target_os="macos")]`.

- [ ] **Step 3:** PIN storage: `pin_file_path()` = `t_config::get_app_data_dir()?.join("hidden_pin.json")`; JSON `{salt_b64, hash_b64, iters}`; `sha2::Sha256` 100k iterations, `rand` 16-byte salt.

- [ ] **Step 4:** `unlock_hidden` command flow: macOS → `lap_auth_unlock()`; 0→set unlocked, "ok"; 1→"cancelled"; 2→"unavailable" (frontend then shows PIN dialog). Windows → `UserConsentVerifier::RequestVerificationAsync` (add `windows = { features = ["Security_Credentials_UI", "Foundation"] }` under `[target.'cfg(target_os="windows")'.dependencies]`). Linux/other → `"unavailable"`. `verify_hidden_pin` → ok sets unlocked true. Windows code is cfg-gated; cannot compile-check on macOS — keep it minimal and clearly marked.

- [ ] **Step 5:** `cargo check`. Commit `feat(hidden): session unlock + OS auth + PIN store`.

### Task 3: Protocol gates + aptabase exit fix (Rust)

**Files:**
- Modify: `src-tauri/src/t_protocol.rs`, `src-tauri/src/t_http.rs` (cfg linux), `src-tauri/src/t_sqlite.rs` (`AFile::is_file_hidden(file_id) -> bool` helper + `is_path_hidden(path)`), `src-tauri/src/main.rs` (guard `flush_events_blocking` with `aptabase_enabled` ~line 457)

- [ ] **Step 1:** `AFile::is_file_hidden(file_id)` — `SELECT COALESCE(is_hidden,0) FROM afiles WHERE id=?1`. In `thumb://` handler: if `is_file_hidden(file_id) && !t_auth::hidden_unlocked()` → 404. In `preview://` handler: same via already-fetched `file.is_hidden`.

- [ ] **Step 2:** `t_http.rs` linux video server: `is_path_hidden` via folder+name lookup → 404. cfg-gated; compile-check not possible on macOS — minimal code.

- [ ] **Step 3:** `main.rs` Exit handler: wrap `app_handle.flush_events_blocking()` in `if aptabase_enabled` (upstream dev-build crash fix).

- [ ] **Step 4:** `cargo check`. Commit `fix(hidden): gate thumb/preview/video on unlock; guard aptabase flush`.

### Task 4: Frontend — menu items, actions, api wrappers, i18n

**Files:**
- Modify: `src-vite/src/common/api.js`, `src-vite/src/common/fileMenu.ts`, `src-vite/src/components/Content.vue` (`handleItemAction` ~3908, near culling ~9014), `src-vite/src/locales/*.json` (all)

**Interfaces:**
- Produces: `setFilesHidden(fileIds, hidden)`, `unlockHidden()`, `lockHidden()`, `hiddenUnlockState()`, `hiddenPinStatus()`, `setHiddenPin(pin)`, `verifyHiddenPin(pin)` api fns; menu actions `'hide'`/`'unhide'`.

- [ ] **Step 1:** api.js wrappers (invoke pattern like `setFileCullingFlag` ~1503).

- [ ] **Step 2:** `fileMenu.ts` — in `buildSingleFileMenu` after the "Set as" submenu object (~line 309): `{ label: f.is_hidden ? localeMsg.value.menu.file.unhide : localeMsg.value.menu.file.hide, icon: markRaw(f.is_hidden ? IconUnhide : IconHide), action: createAction(f.is_hidden ? 'unhide' : 'hide') }`. In `buildSelectionMenu` append same using first selected item's state via `options.selectionMediaKind`/a new `selectionHasVisible` — simplest: pass a `selectionIsHidden` ref like existing options; if any not-hidden → 'hide'.

- [ ] **Step 3:** `handleItemAction`: `'hide'`/`'unhide'` → ids = selectMode ? actionable selected : `[fileList[selectedItemIndex].id]`; `await setFilesHidden(ids, action==='hide')`; success → `await updateContent(true)` + `void tauriEmit('refresh-content')`; error → toast. Unhide only possible while revealed anyway.

- [ ] **Step 4:** i18n: add `menu.file.hide`/`unhide` (+ `hidden.*` dialog keys) to all locale json files (en first; other locales get EN text as fallback values — check repo convention; i18n dir has per-locale files, add to each `menu.file` block).

- [ ] **Step 5:** `pnpm --dir src-vite build` (typecheck via vite build). Commit `feat(hidden): context menu hide/unhide + api + i18n`.

### Task 5: Toolbar toggle + UnlockHiddenDialog + Thumbnail badge

**Files:**
- Modify: `src-vite/src/components/Content.vue` (toolbar ~167 before info TButton, `currentQueryParams` ~3027, fetch dispatch ~5950-6035, watchers), `src-vite/src/components/Thumbnail.vue` (badge overlay), `src-vite/src/components/MediaViewer.vue` if menu shown there too (it reuses fileMenu)
- Create: `src-vite/src/components/UnlockHiddenDialog.vue`

- [ ] **Step 1:** `hiddenUnlocked` + `showHidden` refs; on mount `hiddenUnlockState()` → hiddenUnlocked. Watch query-source change (`currentQuerySource`, `currentQueryParams.searchFolder`, album id) → `showHidden=false` (per spec: reset on navigation).

- [ ] **Step 2:** `includeHidden` plumbing: in the fetch dispatch (~5975-6030) merge `{ includeHidden: showHidden.value }` into params passed to `getQueryFiles`/`getSmartQueryFiles`/`getCollectionFiles` + count/timeline calls.

- [ ] **Step 3:** Toolbar `TButton` before the info button: `:icon="showHidden ? IconUnhide : IconHide"`, `:selected="showHidden"`, tooltip `hidden.show_tooltip`/`hide_tooltip`, `@click="toggleShowHidden"`. Handler: `if (showHidden) { showHidden=false; updateContent(true); return }`; if `!hiddenUnlocked` → `res = await unlockHidden()`; `'ok'`→unlocked; `'unavailable'`→open `UnlockHiddenDialog`; `'cancelled'`→noop. On unlock → `showHidden=true; updateContent(true)`.

- [ ] **Step 4:** `UnlockHiddenDialog.vue` — follow `ModalDialog.vue` usage (see `TaggingDialog.vue`/`MessageBox.vue` for pattern): modes create (first time: PIN + confirm) vs verify; calls `setHiddenPin`/`verifyHiddenPin`; wrong PIN inline error; emits `success`.

- [ ] **Step 5:** `Thumbnail.vue` badge: when `file.is_hidden` truthy, small `IconHide` overlay bottom-corner (match existing badge style for live-photo/rating indicators — grep existing badge markup).

- [ ] **Step 6:** `pnpm --dir src-vite build`, manual run-through. Commit `feat(hidden): reveal toggle + unlock dialog + hidden badge`.

### Task 6: Verification + docs

- [ ] **Step 1:** `cargo test` full, `pnpm build`, `tauri dev` manual test: hide single/multi → files vanish everywhere (grid/map/people/calendar); toggle → Touch ID → hidden appear with badge; switch album → toggle resets; restart → locked again; `sqlite3` confirm `is_hidden` set + `user_version` still 17.
- [ ] **Step 2:** Update spec doc if behavior diverged; commit `docs: hidden photos implementation notes`.
