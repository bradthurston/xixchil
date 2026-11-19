#!/usr/bin/env python3
"""
NRSuite Crack Bridge
====================
Turns a .22000 handshake into a passphrase using a real GPU instead of a phone
CPU. NRSuite exports the hashcat file and stops; this is the missing horsepower
half that lets the phone console carry a crack all the way to a result.

Measured on the reference setup: the phone CPU manages roughly 2-5 kH/s, a
single desktop GPU around 371 kH/s. Same job, same wordlist.

Design decisions
  * storage   - .22000 uploads are 1-20 KB and are the ONLY thing that leaves
                the phone. Wordlists stay on the bridge host, never copied to
                the phone or the radio.
  * retention - jobs older than RETENTION_DAYS are pruned automatically.
  * transport - HTTP/JSON, token-gated (X-Token), bound to 0.0.0.0 so LAN and
                overlay networks both work.
  * gpu       - exactly ONE worker thread, so concurrent jobs queue instead of
                fighting over the single GPU.

Every path below is environment-overridable, so nothing here hardcodes anyone's
home directory; the defaults are just a sensible layout for a fresh clone.

Run:  python3 bridge.py            (or: uvicorn bridge:app --host 0.0.0.0 --port 8099)
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
from pathlib import Path

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse

# ── config ───────────────────────────────────────────────────────────────────
# Every path is environment-overridable; the defaults are only a sensible layout
# so a fresh clone runs without editing this file.
def _env_path(key: str, fallback: Path) -> Path:
    v = os.environ.get(key)
    return Path(v).expanduser() if v else fallback


BASE          = _env_path("BRIDGE_BASE",      Path.home() / "projects" / "crackbridge")
JOBS_DIR      = _env_path("BRIDGE_JOBS",      BASE / "jobs")
WORDLIST_DIR  = _env_path("BRIDGE_WORDLISTS", Path.home() / "wordlists")
RULES_DIR     = _env_path("BRIDGE_RULES",     BASE / "rules")
TOKEN_FILE    = _env_path("BRIDGE_TOKEN_FILE", BASE / "token")
HASHCAT       = os.environ.get("BRIDGE_HASHCAT", "/usr/bin/hashcat")
HASH_MODE     = "22000"
RETENTION_DAYS = int(os.environ.get("BRIDGE_RETENTION_DAYS", "7"))
MAX_UPLOAD    = 2 * 1024 * 1024     # .22000 files are KB-sized; 2 MB is generous
STATUS_TIMER  = 3
PRUNE_EVERY   = 3600

JOBS_DIR.mkdir(parents=True, exist_ok=True)
WORDLIST_DIR.mkdir(parents=True, exist_ok=True)


def load_token() -> str:
    """Token lives in a 0600 file; generated on first run so the phone has one to paste."""
    if TOKEN_FILE.exists():
        t = TOKEN_FILE.read_text().strip()
        if t:
            return t
    t = secrets.token_urlsafe(24)
    TOKEN_FILE.write_text(t + "\n")
    TOKEN_FILE.chmod(0o600)
    return t


TOKEN = load_token()


# ── job model ────────────────────────────────────────────────────────────────
class Job:
    def __init__(self, jid: str, wordlist: str, rules: str):
        self.id = jid
        self.dir = JOBS_DIR / jid
        self.dir.mkdir(parents=True, exist_ok=True)
        self.wordlist = wordlist
        self.rules = rules
        self.state = "queued"
        self.created = time.time()
        self.started: float | None = None
        self.finished: float | None = None
        self.progress = 0.0
        self.speed_hs = 0.0
        self.password: str | None = None
        self.returncode: int | None = None
        self.error: str | None = None

    @property
    def meta_path(self) -> Path:
        return self.dir / "meta.json"

    def snapshot(self) -> dict:
        return {
            "id": self.id,
            "state": self.state,
            "wordlist": self.wordlist,
            "rules": self.rules,
            "created": self.created,
            "started": self.started,
            "finished": self.finished,
            "progress": round(self.progress, 3),
            "speed_hs": round(self.speed_hs, 1),
            "returncode": self.returncode,
            "error": self.error,
        }

    def save(self) -> dict:
        data = self.snapshot()
        data["password"] = self.password
        tmp = self.meta_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(self.meta_path)
        return data


JOBS: dict[str, Job] = {}
QUEUE: list[str] = []
QLOCK = threading.Lock()
WAKE = threading.Event()


def enqueue(j: Job) -> None:
    with QLOCK:
        JOBS[j.id] = j
        QUEUE.append(j.id)
    WAKE.set()


# ── hashcat status parsing ───────────────────────────────────────────────────
# Tolerant on purpose: hashcat's human status uses \r-rewritten "Progress....: n/m (x%)"
# and "Speed.#1....: 371.5 kH/s", while --machine-readable emits tab-separated STATUS lines.
RE_PROGRESS = re.compile(r"(\d+)\s*/\s*(\d+)\s*\((\d+(?:\.\d+)?)%\)")
RE_SPEED    = re.compile(r"([\d.]+)\s*([kMGT]?)\s*H/s")
MULT = {"": 1.0, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}


def parse_status_line(j: Job, line: str) -> None:
    if "STATUS" in line and "\t" in line:
        f = line.split("\t")
        # machine-readable: STATUS\t<session>\tSPEED\t<speed>\t...
        for i, tok in enumerate(f):
            if tok == "SPEED" and i + 1 < len(f):
                try:
                    j.speed_hs = float(f[i + 1])
                except ValueError:
                    pass
        for i, tok in enumerate(f):
            if tok == "PROGRESS" and i + 1 < len(f):
                try:
                    j.progress = float(f[i + 1])
                except ValueError:
                    pass
        return
    m = RE_PROGRESS.search(line)
    if m:
        done, total = int(m.group(1)), int(m.group(2))
        if total:
            j.progress = round(done * 100.0 / total, 4)
    s = RE_SPEED.search(line)
    if s:
        # take the highest-numbered Speed.#N as the aggregate
        try:
            j.speed_hs = float(s.group(1)) * MULT.get(s.group(2), 1.0)
        except ValueError:
            pass


# ── the single GPU worker ────────────────────────────────────────────────────
def run_job(j: Job) -> None:
    j.state = "running"
    j.started = time.time()
    j.save()

    hashfile = j.dir / "handshake.22000"
    outfile  = j.dir / "cracked.txt"
    potfile  = j.dir / "hashcat.potfile"
    wl       = WORDLIST_DIR / j.wordlist

    if not wl.is_file():
        j.state = "failed"
        j.error = f"unknown wordlist: {j.wordlist}"
        j.finished = time.time()
        j.save()
        return

    cmd = [
        HASHCAT, "-m", HASH_MODE, str(hashfile), str(wl),
        "--potfile-path", str(potfile),
        "--outfile", str(outfile), "--outfile-format", "2",
        "--status", "--status-timer", str(STATUS_TIMER),
        "--force", "--quiet",
    ]
    if j.rules and j.rules not in ("", "none"):
        cmd += ["-r", str(RULES_DIR / j.rules)]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except Exception as exc:
        j.state = "failed"
        j.error = f"spawn failed: {exc}"
        j.finished = time.time()
        j.save()
        return

    log = (j.dir / "hashcat.log").open("wb")
    buf = b""
    assert proc.stdout is not None
    while True:
        ch = proc.stdout.read(1)
        if not ch:
            break
        log.write(ch)
        buf += ch
        if ch in (b"\r", b"\n"):
            line = buf.decode("utf-8", "replace").strip()
            buf = b""
            if line:
                parse_status_line(j, line)
                j.save()
    proc.wait()
    log.close()

    j.returncode = proc.returncode
    j.finished = time.time()

    if outfile.exists() and outfile.stat().st_size:
        j.password = outfile.read_text(errors="replace").strip().splitlines()[0]
        j.state = "cracked"
        j.progress = 100.0
    elif proc.returncode in (0, 1):
        # hashcat exit codes: 0 = OK, 1 = keyspace EXHAUSTED (nothing found).
        # Getting this backwards reports a clean miss as a crash - it did exactly that.
        j.state = "exhausted"
        j.progress = 100.0
    else:
        # 2 = aborted (ctrl-c), 3 = checkpoint, 4+ = error
        j.state = "failed"
        j.error = f"hashcat exit {proc.returncode} - see hashcat.log"
    j.save()


def worker_loop() -> None:
    while True:
        jid = None
        with QLOCK:
            if QUEUE:
                jid = QUEUE.pop(0)
        if jid is None:
            WAKE.wait(timeout=1.0)
            WAKE.clear()
            continue
        try:
            run_job(JOBS[jid])
        except Exception as exc:  # never let the worker die
            j = JOBS.get(jid)
            if j:
                j.state = "failed"
                j.error = f"worker crash: {exc}"
                j.finished = time.time()
                j.save()


def prune_loop() -> None:
    cutoff_secs = RETENTION_DAYS * 86400
    while True:
        now = time.time()
        for d in JOBS_DIR.iterdir():
            if not d.is_dir():
                continue
            try:
                if now - d.stat().st_mtime > cutoff_secs:
                    with QLOCK:
                        JOBS.pop(d.name, None)
                    shutil.rmtree(d, ignore_errors=True)
            except OSError:
                pass
        time.sleep(PRUNE_EVERY)


threading.Thread(target=worker_loop, daemon=True).start()
threading.Thread(target=prune_loop, daemon=True).start()


TERMUX_SHEBANG = "#!/data/data/com.termux/files/usr/bin/bash"


# ── http api ─────────────────────────────────────────────────────────────────
app = FastAPI(title="NRSuite Crack Bridge", version="1.0.0")


def check_token(x_token: str | None) -> None:
    if not x_token or not secrets.compare_digest(x_token, TOKEN):
        raise HTTPException(status_code=401, detail="bad or missing X-Token")


@app.get("/crack.sh")
def get_crack_script():
    """Serve the phone-side script, so Termux setup is one curl instead of a paste.

    The shebang is rewritten for the client. Android has neither /usr/bin/env nor
    /bin/sh, so `#!/usr/bin/env bash` dies with "bad interpreter: No such file or
    directory" and the script can only be run as `bash crack.sh`. Serving a Termux
    shebang instead makes plain `./crack.sh <file>` work. The file on disk keeps
    its portable shebang so it still runs directly on this host.
    """
    p = BASE / "crack.sh"
    if not p.is_file():
        raise HTTPException(status_code=404, detail="crack.sh missing on the bridge host")
    text = p.read_text()
    if text.startswith("#!"):
        rest = text.partition("\n")[2]
        text = TERMUX_SHEBANG + "\n" + rest
    return PlainTextResponse(
        text,
        headers={"Content-Disposition": 'attachment; filename="crack.sh"'},
    )


@app.get("/health")
def health():
    return {
        "ok": True,
        "hashcat": HASHCAT,
        "mode": HASH_MODE,
        "queued": len(QUEUE),
        "wordlists": sorted(p.name for p in WORDLIST_DIR.iterdir() if p.is_file()),
        "rules": sorted(p.name for p in RULES_DIR.iterdir() if p.is_file()) if RULES_DIR.is_dir() else [],
    }


@app.get("/wordlists")
def wordlists(x_token: str | None = Header(default=None)):
    check_token(x_token)
    out = []
    for p in sorted(WORDLIST_DIR.iterdir()):
        if p.is_file():
            out.append({"name": p.name, "size": p.stat().st_size,
                        "lines": sum(1 for _ in p.open("rb"))})
    return {"wordlists": out}


@app.post("/crack")
async def crack(
    file: UploadFile = File(...),
    wordlist: str = Form("rockyou.txt"),
    rules: str = Form("none"),
    x_token: str | None = Header(default=None),
):
    check_token(x_token)

    blob = await file.read()
    if len(blob) > MAX_UPLOAD:
        raise HTTPException(status_code=413, detail=f"file too big (>{MAX_UPLOAD} bytes)")
    if not blob:
        raise HTTPException(status_code=400, detail="empty file")

    text = blob.decode("utf-8", "replace")
    if "WPA*" not in text:
        raise HTTPException(status_code=400, detail="no WPA* line found - not a hashcat .22000?")

    jid = secrets.token_hex(6)
    j = Job(jid, wordlist, rules)
    (j.dir / "handshake.22000").write_bytes(blob)
    j.save()
    enqueue(j)

    return JSONResponse({"job_id": jid, "state": "queued"}, status_code=202)


def get_job(job_id: str) -> Job:
    with QLOCK:
        j = JOBS.get(job_id)
    if j:
        return j
    # tolerate a restart by reloading from disk
    d = JOBS_DIR / job_id
    meta = d / "meta.json"
    if not d.is_dir() or not meta.is_file():
        raise HTTPException(status_code=404, detail="no such job")
    data = json.loads(meta.read_text())
    j = Job(job_id, data.get("wordlist", ""), data.get("rules", "none"))
    j.state = data.get("state", "unknown")
    j.created, j.started, j.finished = data.get("created"), data.get("started"), data.get("finished")
    j.progress, j.speed_hs = data.get("progress", 0.0), data.get("speed_hs", 0.0)
    j.password, j.error = data.get("password"), data.get("error")
    j.returncode = data.get("returncode")
    return j


@app.get("/jobs/{job_id}")
def job_status(job_id: str, x_token: str | None = Header(default=None)):
    check_token(x_token)
    return get_job(job_id).snapshot()


@app.get("/jobs/{job_id}/result")
def job_result(job_id: str, x_token: str | None = Header(default=None)):
    check_token(x_token)
    j = get_job(job_id)
    body = j.snapshot()
    body["password"] = j.password
    body["elapsed"] = round((j.finished or time.time()) - j.started, 2) if j.started else None
    return body


if __name__ == "__main__":
    import uvicorn
    print(f"token: {TOKEN}")
    uvicorn.run(app, host="0.0.0.0", port=8099, log_level="warning")
