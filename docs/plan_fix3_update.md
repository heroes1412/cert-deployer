# Implementation Plan: Clarify Status & Add Global Pre/Post Commands

> **Goal:** 
> 1. Update `cert-agent check` status to explicitly distinguish `SERVER NOT FOUND` and `LOCAL NOT FOUND`.
> 2. Add `global_pre_cmd` and `global_post_cmd` configuration support in `config.yaml`.

---

## Detailed Modifications

### Task 1: Update `client/internal/config/config.go`
- Add `GlobalPreCmd` (`yaml:"global_pre_cmd"`) and `GlobalPostCmd` (`yaml:"global_post_cmd"`).
- Fallback alias: If `GlobalPreCmd` is empty, use root `PreCmd`. If `GlobalPostCmd` is empty, use root `PostCmd`.

### Task 2: Update `client/cmd/check.go`
- Set status `SERVER NOT FOUND` when Server API returns 404.
- Set status `LOCAL NOT FOUND` when local cert file does not exist on disk.
- Adjust ASCII table column width to 16 chars for STATUS column to fit `SERVER NOT FOUND` and `LOCAL NOT FOUND`.

### Task 3: Update `client/cmd/sync.go`
- Execute `GetGlobalPreCmd()` ONCE before any per-cert pre_cmd / sync starts.
- Execute `GetGlobalPostCmd()` ONCE at the end of all cert syncs if at least one cert was updated.

### Task 4: Verification & Push
- Build binaries using `build.bat`.
- Test execution and push updates to GitHub.
