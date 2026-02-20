# setup.md — PsyClaw / OpenClaw Infra Setup (Win11 Pro → Hyper-V Ubuntu → Docker → Gateway + Runner)

> This document captures **only the successful, current setup path** up to the present checkpoint.
> Language policy for this file: **English only**.

---

## 1) Target Architecture (Current)

### 1.1 Host → VM → Docker
- **Host OS:** Windows 11 Pro (kept as the stable “metal” layer).
- **Virtualization:** Hyper‑V VM running Ubuntu.
- **Execution:** Docker Engine inside Ubuntu VM.

### 1.2 Core Security Invariants (Current)
- **Zero‑Trust Execution:** Gateways / Dev Agent do **not** get `docker.sock`.
- **Runner executes jobs** via a constrained interface (through a socket proxy) and **allowlist-only** job definitions.
- **Ephemeral jobs:** each build/test runs in a **one-shot container** (`--rm` semantics at job layer).
- **Single conversational interface:** user talks to **one Dev Agent**; it orchestrates roles internally (auditor/build/test/verify) via Runner.

---

## 2) Disk & Path Layout (Ubuntu VM)

### 2.1 Mounted disks (current)
- **/srv/data** (label: `CLAW_DATA`, ext4): durable state, configs, projects, artifacts.
- **/srv/cache** (label: `CLAW_CACHE`, ext4): caches and “trash” storage.
- Docker Root is already moved to: **`/srv/cache/docker`**

### 2.2 OpenClaw base directories (current)
- `/srv/data/openclaw/` contains:
  - `gw-admin/` – gateway instance (“admin bubble”)
  - `repo/` – local repos
  - `upstream-openclaw/` – upstream source snapshot(s)
  - `artifacts/` – shared artifacts (project-level)
  - `infra/`, `node-admin/` – other infra / nodes (as created)
- `/srv/cache/openclaw/` is used for Runner caches.

---

## 3) Docker baseline verification (Ubuntu VM)

Run these to confirm the environment (examples shown; your values may differ):

```bash
uname -a
lsb_release -a || cat /etc/os-release
docker --version
docker compose version || docker-compose --version
docker info | sed -n '1,60p'
df -hT
lsblk -f
```

Current known-good baseline:
- Ubuntu 24.04 LTS
- Docker Engine 29.x
- Docker Compose v5.x
- Docker Root Dir: `/srv/cache/docker`

---

## 4) OpenClaw Gateway (gw-admin) — Known Good Operation

### 4.1 Running containers (typical)
Gateway and Postgres are running as containers:
- `dkr-gw-admin` (image: `openclaw:local`)
- `dkr-postgres` (image: `pgvector/pgvector:pg16`)

Check:
```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
```

### 4.2 Canonical management rule (IMPORTANT)
**Do NOT run CLI as a separate container** to manage the gateway.
The stable, canonical approach is:

> Always run OpenClaw CLI **inside** the running gateway container via `docker exec`.

Canonical commands (examples):

```bash
docker exec -it dkr-gw-admin node dist/index.js health
docker exec -it dkr-gw-admin node dist/index.js devices list
docker exec -it dkr-gw-admin node dist/index.js devices approve --latest
docker exec -it dkr-gw-admin node dist/index.js devices reject --latest
docker exec -it dkr-gw-admin node dist/index.js devices rotate <role>
docker exec -it dkr-gw-admin node dist/index.js dashboard --no-open
```

> Note: In some environments the actual container name is `dkr-claw-gw-admin`.
> Standardize on the real container name you run in `docker ps`. The **principle** stays the same.

### 4.3 Gateway state directory (current)
Known state location:
- `/srv/data/openclaw/gw-admin/config`

This directory contains device pairing state such as:
- `devices/pending.json`
- `devices/paired.json`
- `openclaw.json`

---

## 5) Runner Stack (Socket Proxy + Go Runner) — Current Checkpoint

### 5.1 Design rules (current)
- Runner is a **separate service** from the gateway.
- Runner talks to Docker via **socket proxy** (no direct `docker.sock` exposure to gateway/dev agent).
- **Tools live inside per-job Docker images.**
- Shared cache is allowed for speed:
  - **Gradle/Maven cache is shared at:** `/srv/cache/openclaw/runner/gradle`
- **No shared host Android SDK** (we explicitly do not implement the optional SDK cache optimization).

### 5.2 Runner directories (created and confirmed)
Data (durable):
- `/srv/data/openclaw/runner/compose`
- `/srv/data/openclaw/runner/jobs`
- `/srv/data/openclaw/runner/audit`
- `/srv/data/openclaw/runner/reports`

Cache (non-durable / speed):
- `/srv/cache/openclaw/runner/work`
- `/srv/cache/openclaw/runner/gradle`
- `/srv/cache/openclaw/runner/tmp`

Creation commands:

```bash
sudo mkdir -p /srv/data/openclaw/runner/{compose,jobs,audit,reports}
sudo mkdir -p /srv/cache/openclaw/runner/{work,gradle,tmp}

sudo chown -R psy:psy /srv/data/openclaw/runner
sudo chown -R psy:psy /srv/cache/openclaw/runner
```

### 5.3 Socket Proxy + Runner compose (current)
File:
- `/srv/data/openclaw/runner/compose/docker-compose.yml`

Services:
- `dkr-claw-socket-proxy` (tecnativa/docker-socket-proxy)
  - Mounted: `/var/run/docker.sock:/var/run/docker.sock:ro`
  - Enabled: `CONTAINERS=1`, `IMAGES=1`
  - Disabled: networks/volumes/system/exec/etc.
- `dkr-claw-runner` (Go runner image: `openclaw-runner:local`)
  - Talks to proxy via: `DOCKER_HOST=tcp://claw-socket-proxy:2375`
  - Exposes HTTP API on localhost only:
    - `127.0.0.1:18888 -> 8080`

Bring up:
```bash
cd /srv/data/openclaw/runner/compose
docker compose up -d
```

### 5.4 Verify proxy connectivity
From inside runner container:

```bash
docker exec -it dkr-claw-runner sh -lc 'apk add --no-cache curl >/dev/null && curl -sS http://claw-socket-proxy:2375/_ping && echo'
```

Expected output:
- `OK`

### 5.5 Go Runner MVP (current)
Runner source:
- `/srv/data/openclaw/runner/runner-go/`

Built local image:
- `openclaw-runner:local`

The current HTTP endpoints:
- `GET /healthz` → returns JSON health status
- `POST/GET /v1/jobs/run` → currently returns `501 Not Implemented` (intentional checkpoint)

Health check:
```bash
curl -sS http://127.0.0.1:18888/healthz && echo
```

Expected output (example):
```json
{"ok":true,"service":"openclaw-runner-mvp","time_utc":"...","docker_host":"tcp://claw-socket-proxy:2375","data_dir":"/runner-data","cache_dir":"/runner-cache"}
```

Logs / restart policy:
```bash
docker logs --tail 50 dkr-claw-runner
docker inspect dkr-claw-runner --format '{{.HostConfig.RestartPolicy.Name}}'
```

Expected:
- Logs show listening and health requests
- Restart policy: `unless-stopped`

---

