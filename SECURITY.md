# Security policy

Xixchil is an offensive tool. It captures WPA handshakes and recovers passphrases, and the bridge
will run hashcat on whatever it is handed. That is the product, not a vulnerability — a report that
"this cracks Wi-Fi" or "the deauth attack kicks clients off" is working as intended, and it will be
closed.

What *is* in scope is anything that makes the tool unsafe for the person running it, or that it
claims and does not deliver.

## In scope

- **The bridge** (`bridge/bridge.py`) — authentication bypass, the token check, an endpoint that
  leaks more than it should, command injection through a job's parameters, path traversal in a
  wordlist or rule name, writing outside its own directories.
- **The firmware** (`firmware/`) — memory safety and parser bugs reachable from the air. Every frame
  it processes is attacker-controlled input by definition: a malformed beacon, probe request or
  EAPOL frame that panics the board, corrupts the capture, or executes something is a real finding.
- **The app** (`app/`) — the USB-serial bridge protocol, the import path for `.pcap` and `.22000`
  files, and the native plugin. A file that comes in from outside and does something other than
  parse is a finding.
- **Anything that leaks the operator's own data** — real network names or addresses escaping into a
  log, an export, or a published artifact is a privacy bug in this project's terms, even when it is
  not a security bug in someone else's.

## Out of scope

- Capturing handshakes, cracking passphrases, deauth, Karma/Mana, the evil twin portal, or any other
  capability, used against a network the operator owns or has written permission to test.
- Missing features, and the limitations listed in the README — 5 GHz injection, MouseJack, BadUSB.
- Vulnerabilities in hashcat, the ESP32 Arduino core, ESP-IDF, Capacitor or a plugin. Report those
  upstream; if it turns out we are the ones invoking them badly, that is in scope here.
- Anything requiring an attacker who already has code execution on the host.

## Reporting

**Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)**
— the *Security* tab, *Report a vulnerability*. That keeps the details private while a fix is
worked out, and it is the only channel that will be read promptly.

Please include what it affects (bridge, firmware, app), the version or commit, and the smallest
reproduction you can manage. For firmware, the exact frame bytes matter more than a description of
them.

If private reporting is unavailable, open a normal issue that says you have a security report and
nothing more, and a private channel will be arranged. Do not put the details in the issue.

This is a single-maintainer project with no funding and no embargo promises. Expect a best-effort
response — usually a few days — and credit in the fix commit if you want it. There is no bug bounty.

## Already-known and accepted

Stated here so they are not reported as surprises:

- **The bridge speaks plain HTTP.** No TLS, deliberately, because the expected deployment is a LAN
  or a WireGuard/Tailscale tunnel. `bridge/README.md` says what that costs and what to do about it.
- **The bridge binds `0.0.0.0` by default**, and the token is the only gate. `BRIDGE_HOST` changes
  it. Same reasoning: the phone has to reach it.
- **`/health` answers without a token**, by design, and returns nothing but liveness unless the
  token is presented.
- **The device persists nothing.** "Pull the power and the board is blank" is a feature, and
  "evidence disappeared" is not a bug report unless the app also failed to keep it.
