# PROJECT_FILES.md — clup Repository Inventory (Allowlist)

This repository is **public**. It must contain **only Infrastructure-as-Code and source code**.
**No live data, no secrets, no runtime state** are allowed in Git.

---

## 1) Golden Rules

1. **Default-deny**: everything is ignored by default. Only explicitly allowlisted paths are versioned.
2. **Secrets live only in ignored `.env` files** (or other ignored secret stores). Never commit secrets.
3. **No live state**: no device pairing state, no DB data, no workspaces, no logs, no caches, no artifacts.
4. **Reproducible infra**: commit compose files, templates, and source code required to rebuild services.

---

## 2) Allowed (Committed) Paths

### 2.1 Documentation
- `README.md`
- `LICENSE`
- `docs/**`
- `setup.md`
- `MASTER_SPEC.md`
- `BASELINE_CHECKPOINT.md`
- `PROJECT_FILES.md` (this file)
- `RUNBOOK.md`
- `ARCHITECTURE.md`
- `JOBS_ALLOWLIST.md`

### 2.2 Runner (Go) + Compose
- `runner/compose/docker-compose.yml`
- `runner/compose/README.md` (optional)
- `runner/runner-go/**` (Go sources, Dockerfile, configs)

### 2.3 Infra compose (safe only)
- `infra/docker-compose.yml`
- `infra/README.md` (optional)

### 2.4 Gateway compose templates (NO state)
- `gw-admin/docker-compose.yml`
- `gw-admin/README.md` (optional)

> Gateway state/config and `.env` are explicitly forbidden (see section 3).

---

## 3) Forbidden (Must NEVER be Committed)

### 3.1 Secrets / Env
- Any `.env` file: `.env`, `.env.*`
- Any file containing tokens/keys/passwords
- Any certificate or key material: `*.pem`, `*.key`, `*.p12`, `*.jks`

### 3.2 OpenClaw Gateway live state
- `gw-admin/config/**` (paired devices, pending, openclaw.json, etc.)
- `gw-admin/workspace/**`
- `gw-*/config/**`, `gw-*/workspace/**` (all gateway instances)

### 3.3 Runner live outputs / state
- `runner/jobs/**`
- `runner/audit/**` (runtime audit outputs)
- `runner/reports/**` (runtime reports)
- `runner/logs/**`

### 3.4 Databases and dumps
- Any Postgres data directories (e.g. `postgres/**`, `pgdata/**`)
- Any dumps: `*.sql`, `*.dump`, `*.backup`

### 3.5 Caches / dependencies / artifacts
- `artifacts/**`
- `.pnpm-store/**`
- `**/node_modules/**`
- `**/.gradle/**`
- `**/build/**`, `**/dist/**`, `**/out/**`, `**/target/**`
- Any packaged artifacts: `*.apk`, `*.aab`, `*.aar`, `*.jar`, archives `*.zip`, `*.tar*`

### 3.6 Upstream or local clones
- `repo/**`
- `upstream-openclaw/**`

---

## 4) Practical Workflow

- Place the repo at: `/srv/data/openclaw/clup` (or another stable location).
- Keep runtime data outside repo and mount it into containers as needed.
- Use ignored `.env` files for secrets, and commit only `.env.example` templates (if needed).

---

## 5) Quick Self-Check Before Pushing

Run:

```bash
git status
git diff --stat
git grep -nE '(token|secret|password|BEGIN PRIVATE KEY)' || true
```

If anything suspicious shows up, **do not push** until cleaned.
