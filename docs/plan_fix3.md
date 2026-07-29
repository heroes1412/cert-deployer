# Implementation Plan: Fix 3 Issues

> **Goal:** Address all 9 issues specified in `Fix3.txt`.

---

## Detailed Task Breakdown

### Task 1: Server Web Admin UI - Download Cert/Key Buttons (Issue 1)
- Modify `server/templates/index.html`:
  - Add **Download Cert** and **Download Key** buttons in the Add/Edit Certificate modal.
  - Implement JavaScript helper `downloadFile(filename, content)` using Blob & Data URL to save `.crt` and `.key` files directly from the browser.

### Task 2: Client Config YAML Preprocessing & Path Handling (Issues 2 & 4)
- Modify `client/internal/config/config.go`:
  - Implement `preprocessYAML(data []byte) []byte`: Fix invalid YAML backslash escapes (e.g. `\v`, `\i`, `\L`, `\S`, `\e`, `\p`, single Windows backslashes in paths) by converting unescaped backslashes to forward slashes `/` before `yaml.Unmarshal`.
  - Add `PreCmd` and `PostCmd` fields to `CertMapping` struct for per-certificate command execution.

### Task 3: Client `check` Command Updates (Issues 3 & 9)
- Modify `client/cmd/check.go`:
  - Change status from `SERVER ERR` to `NOT FOUND` when HTTP status is 404.
  - Reorder ASCII table columns to: `SERVERCERT NAME | SERVER EXPIRATION | LOCAL EXPIRATION | STATUS`.

### Task 4: Per-Cert Commands & Local File Check in `sync` Command (Issues 5, 6 & 7)
- Modify `client/cmd/sync.go`:
  - Check if local `certfile` and `keyfile` exist before attempting sync. If missing, log warning `[WARN] Local file missing for cert %s. Skipping update.` and skip downloading.
  - Execute per-certificate `pre_cmd` before downloading cert and per-certificate `post_cmd` right after updating that cert.

### Task 5: Default Config Path (Issue 8)
- Modify `client/cmd/root.go`:
  - If `-c` / `--config` is not explicitly provided, check if `./config.yaml` exists in the current working directory. If so, default to `./config.yaml`. Otherwise default to `/etc/cert-agent/config.yaml`.

### Task 6: Verification & Build
- Build server and client binaries (`build.bat`).
- Verify compilation and test behaviors.
- Commit and push to GitHub repository.
