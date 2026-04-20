# reNgine → paraKang Rename: Complete Findings Report

**Date:** April 20, 2026  
**Status:** Project partially renamed - critical broken references remain

---

## Summary
The project was renamed from **reNgine** to **paraKang**, but the rename was incomplete. Main application code uses `paraKang` module, but git hooks, configuration scripts, and documentation still reference the old `reNgine` name, causing broken paths and potential runtime errors.

---

## 1. CRITICAL ISSUES - Must Fix

### 1.1 Git Hook - Broken Post-Commit
**File:** `.git/hooks/post-commit` (Line 5)  
**Issue:** Points to non-existent directory
```
git rev-parse HEAD > "${REPO_ROOT}/web/reNgine/.repo_head"
```
**Should be:**
```
git rev-parse HEAD > "${REPO_ROOT}/web/paraKang/.repo_head"
```
**Impact:** ⚠️ **HIGH** - Git hook will fail on every commit if executed

---

## 2. FILES CONTAINING "reNgine" REFERENCES

### 2.1 Git Metadata (Non-source)
- `.git/logs/HEAD` - Commit log message containing "upstream reNgine"
- `.git/logs/refs/heads/main` - Same commit message reference

**Note:** These are read-only git history files. No action needed unless rewriting history.

---

## 3. CONFIGURATION FILES - Updated ✅
These files have been successfully updated to use `paraKang`:

- `docker-compose.yml` - References `parakang` containers/networks
- `docker-compose.dev.yml` - References `paraKang` module paths
- `docker-compose.setup.yml` - Uses new naming
- `.env.example` - Uses `parakang` for containers/DB
- `config/nginx/parakang.conf` - NGINX config references `paraKang` backend
- `web/paraKang/settings.py` - Main settings file uses:
  - `ROOT_URLCONF = 'paraKang.urls'`
  - `WSGI_APPLICATION = 'paraKang.wsgi.application'`
  - References to `paraKang` module
- `web/paraKang/urls.py` - Main URL routing file
- `README.md` - Documentation references `paraKang` (docker commands use `parakang-` prefix)
- `CONTRIBUTORS.md` - References `paraKang`

---

## 4. STATIC FILES AND CSS REFERENCES - OK ✅
- Static file paths use `/staticfiles/` (correct)
- Nginx configuration points to correct static root: `/usr/src/app/staticfiles/`
- Django settings: `STATIC_URL = '/staticfiles/'`
- No broken CSS or static asset references found

---

## 5. API ENDPOINTS - Updated ✅
- API schema title: "paraKang API"
- Update endpoint: `/api/parakang/update/` ✅
- All documented endpoints reference `parakang` (lowercase for URLs)

---

## 6. DOCKER-RELATED REFERENCES - OK ✅
All docker-compose files updated:
- Network: `parakang_network` ✅
- Database container: Uses `parakang` user/db ✅
- Containers named: `parakang-web-1`, `parakang-celery-1`, etc. ✅
- Image: `docker.pkg.github.com/yogeshojha/parakang/parakang:latest` ✅

---

## 7. DOCUMENTATION FILES NEEDING UPDATE

### 7.1 Audit Report
**File:** `RENGINE_DEEP_AUDIT_V2.md`  
**Issue:** Filename and content still use `reNgine` terminology  
**Recommendation:** Rename to `PARAKANG_DEEP_AUDIT_V2.md` and update content

---

## 8. PYTHON MODULE REFERENCES

### Status Check Result:
✅ Main module has been renamed: `web/paraKang/` exists  
✅ Settings imports use `paraKang` correctly  
✅ URL config uses `paraKang.urls`  
✅ Middleware references use `paraKang` in new settings file  

**Note:** Old references like `from reNgine.middleware import ...` would fail if they still exist in older config files or migrations. Codebase appears clean on primary modules.

---

## 9. ENVIRONMENT VARIABLES & CONSTANTS

### Updated (✅)
- `PARAKANG_HOME` - Used in settings.py
- `PARAKANG_RESULTS` - Used in settings.py  
- `PARAKANG_CACHE_ENABLED` - Used in settings.py
- `PARAKANG_RECORD_ENABLED` - Used in settings.py
- `PARAKANG_RAISE_ON_ERROR` - Used in settings.py
- `PARAKANG_CURRENT_VERSION` - Set from `.version` file

### Potential Legacy (⚠️)
- Check if any shell scripts or deployment files reference `RENGINE_HOME` or similar

---

## 10. ACTION ITEMS REQUIRED

### Priority 1 - CRITICAL
- [ ] Fix `.git/hooks/post-commit` to reference `/web/paraKang/.repo_head` instead of `/web/reNgine/.repo_head`

### Priority 2 - IMPORTANT
- [ ] Rename `RENGINE_DEEP_AUDIT_V2.md` → `PARAKANG_DEEP_AUDIT_V2.md`
- [ ] Search deployment scripts (`install.sh`, `update.sh`) for any old references
- [ ] Verify no migrations or legacy configuration files use old `reNgine` module paths

### Priority 3 - DOCUMENTATION
- [ ] Update commit messages/git history references in documentation if needed
- [ ] Review any internal documentation or runbooks for `reNgine` terminology

---

## 11. TESTING CHECKLIST

After fixes, verify:
- [ ] Git commits execute successfully (post-commit hook doesn't error)
- [ ] `docker compose up` works without path errors
- [ ] Django migrations run without import errors
- [ ] Static files load correctly (`/staticfiles/` paths work)
- [ ] API endpoints respond (especially `/api/parakang/update/`)
- [ ] Celery tasks execute without module import errors
- [ ] URL routing works (admin, dashboard, API)

---

## 12. SUMMARY TABLE

| Category | Status | Files Affected |
|----------|--------|-----------------|
| Main Module | ✅ Renamed | `/web/paraKang/` |
| Django Settings | ✅ Updated | `paraKang/settings.py` |
| URL Routing | ✅ Updated | `paraKang/urls.py` |
| Docker Config | ✅ Updated | `docker-compose*.yml` |
| Environment | ✅ Updated | `.env.example` |
| API Schema | ✅ Updated | `api/urls.py`, `api/views.py` |
| Static Files | ✅ OK | No broken paths |
| **Git Hooks** | ⚠️ **BROKEN** | `.git/hooks/post-commit` |
| **Documentation** | ⚠️ **Stale** | `RENGINE_DEEP_AUDIT_V2.md` |

---

## 13. NEXT STEPS

1. **Immediate:** Fix the git hook (Priority 1)
2. **Follow-up:** Rename and update audit documentation (Priority 2)  
3. **Verify:** Run the testing checklist above
4. **Deploy:** Test in staging environment before production

