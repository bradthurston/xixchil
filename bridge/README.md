# The Xixchil crack bridge

The other half of the crack loop. The app turns a captured handshake into a hashcat `22000`
line; **this service turns that line into a password.**

Without it, the loop stops at a file — which is precisely where every other tool in this space
stops. NRSuite exports the hashcat file and leaves you to find hashcat yourself. Marauder,
Bruce and Flipper do not crack at all.

---

## Why it exists

Measured, not assumed:

| Where | Rate |
|---|---|
| Phone CPU | ~2-5 kH/s |
| One desktop GPU | ~371 kH/s |

That is not a tuning difference, it is roughly two orders of magnitude. So the architecture is
deliberate: **the phone is the console, the GPU is the muscle.** The bridge is small on purpose
— it holds no radio state and knows nothing about 802.11. It takes a hash and gives back an
answer.

```
phone  ──.22000 + X-Token──►  bridge  ──►  hashcat -m 22000  ──►  passphrase  ──►  phone
```

---

## Run it

It needs Python 3, `fastapi`, `uvicorn` and `hashcat` on `PATH`.

```bash
cd bridge
python3 -m pip install fastapi uvicorn python-multipart
python3 bridge.py                 # binds 0.0.0.0:8099
# or: uvicorn bridge:app --host 0.0.0.0 --port 8099
```

On first run it generates a token and writes it to `./token` with mode `0600`. That token is the
only thing standing between the internet and your GPU, so treat it as a password — see
[Security](#security).

Then point the app at it. Either paste the URL and token into the app's settings, or put them in
the app's `bridge-defaults.js` (gitignored — copy `bridge-defaults.example.js`).

### On the phone, under Termux

`termux-setup.sh` does the whole install, including the two non-obvious bits: Termux's Python
lives in a private `run-as` SELinux domain so `hashcat` has to be a wrapper that re-enters it,
and `runsvdir` will not start as an Android background service without `sv-enable`. Both are
already handled.

```bash
BRIDGE_URL=http://192.168.1.50:8099 BRIDGE_TOKEN=<your token> bash termux-setup.sh
```

`termux-run.sh` starts it, `termux-start-services.sh` wires it into Termux's service manager.
`crack.sh` is a small CLI client for the same API if you want to drive it from a shell.

---

## Configuration

Every path is environment-overridable, so nothing hardcodes anyone's home directory.

| Variable | Default | Meaning |
|---|---|---|
| `BRIDGE_BASE` | `~/projects/crackbridge` | Root for jobs and rules |
| `BRIDGE_JOBS` | `$BRIDGE_BASE/jobs` | Per-job work directories |
| `BRIDGE_WORDLISTS` | `~/wordlists` | Where hashcat wordlists live |
| `BRIDGE_RULES` | `$BRIDGE_BASE/rules` | hashcat rule files |
| `BRIDGE_TOKEN_FILE` | `$BRIDGE_BASE/token` | Token file (created `0600` if absent) |
| `BRIDGE_HASHCAT` | `/usr/bin/hashcat` | hashcat binary |
| `BRIDGE_RETENTION_DAYS` | `7` | Jobs older than this are pruned |

---

## API

All of it is JSON over HTTP. Send the token as an `X-Token` header.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | no | Liveness, hashcat path, mode, queue depth, visible wordlists |
| `GET` | `/wordlists` | yes | What the bridge can see |
| `POST` | `/crack` | yes | Multipart upload: the `.22000` file, plus wordlist / rules / mask |
| `GET` | `/jobs/{id}` | yes | Job state and progress |
| `GET` | `/jobs/{id}/result` | yes | The passphrase, or an exhausted/cancelled verdict |
| `GET` | `/crack.sh` | no | Serves the CLI client (handy for bootstrapping on Termux) |

`/health` is deliberately unauthenticated so a monitor can check liveness. Everything that costs
GPU time, or that would reveal your wordlists, requires the token.

**Exactly one worker thread** handles GPU jobs. Concurrent requests queue rather than fight over
the card — a second job makes the first one slower, not both of them wrong.

---

## Security

Read this before exposing it.

- **The token is a password.** It protects a service that will happily run your GPU. Anyone with
  it can submit work.
- **The service binds `0.0.0.0`** so LAN and overlay networks both work. That means the token is
  the *only* control. If you would not put the token in a public repo, do not put it on a host
  that is reachable from one. **Never commit `token`.**
- **Rotate by deleting the file** and restarting; a new one is generated. Then update the app.
- **`X-Token` is compared with `secrets.compare_digest`**, so the check does not leak its answer
  through timing.

**What leaves the phone:** a `.22000` file, 1-20 KB. That is the entire egress. Wordlists and
rules stay on the bridge host and are never copied to the phone.

**Storage:** each job gets a directory under `$BRIDGE_JOBS`. **Retention:** anything older than
`BRIDGE_RETENTION_DAYS` is pruned on a timer. A job directory may contain a `.potfile` with a
cracked passphrase — that is a real secret, sitting on disk, on purpose, until it is pruned.

---

## What is not in this repo

- **Wordlists.** Large, separately licensed, and personal. Put them in `$BRIDGE_WORDLISTS`
  (`~/wordlists` by default). `GET /wordlists` will list whatever is there.
- **hashcat rules.** Same reasoning — `$BRIDGE_RULES`.
- **Job history.** Everything under `jobs/` is your own crack results. Gitignored, and it must
  stay that way: it contains hashes and, on success, live passphrases.

---

## Licence

MIT, same as the rest of the project.
