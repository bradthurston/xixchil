// logitacker.js — the LOGITacker lane: drive the nRF52840 dongle (PCA10059) over USB serial.
//
// This is a TEXT SHELL, not a framed protocol. The ESP32 board on the other lane
// speaks `[0xAD 0xDE][type][id][len][JSON]`; the dongle speaks English. Everything
// below was read off the live device (LOGITacker v0.2.3-beta) rather than guessed,
// and each of these facts is load-bearing:
//
//   * The prompt is `LOGITacker (<mode>) $ ` and it has NO trailing newline. Async
//     `<info>` lines are printed *after* the prompt and land on the same line as
//     it. So the prompt is a RECORD SEPARATOR, not a line prefix — splitting the
//     stream by newline cannot work. That is the single most important thing here.
//   * Lines end `\r\r\n`, and the shell wraps its own output in ANSI colour and
//     cursor escapes (`\x1b[24D`, `\x1b[J` as well as `\x1b[1;32m`). Strip them,
//     or the prompt pattern matches on escaped garbage.
//   * The shell echoes the command back, so the first line of a reply is your own
//     command returning.
//   * It has NO `help`, `info`, `list`, `mode`, `idle`, `config` or `logging`
//     command; unknown commands answer `<cmd>: command not found`. It does have
//     `devices` and `script`. Assume nothing about Unix-ish names.
//
// Nothing here touches the DOM or `window`, so tools/verify_logitacker.mjs can
// drive the whole thing against captured bytes with no dongle attached.

export const LOGITACKER_BAUD = 115200;

// The prompt is the only reliable record boundary. Captured: modes seen are
// `discover` (idle/hunting), plus inject/sniff while running a script or sniffing.
export const PROMPT_SOURCE = 'LOGITacker \\(([^)]*)\\) \\$ ';
const PROMPT_RE = new RegExp(PROMPT_SOURCE, 'g');

// CSI sequences: colour, reset (`\x1b[m`), cursor moves (`\x1b[24D`, `\x1b[14C`,
// erase (`\x1b[J`). The bare `\x1b[m` is why the numeric class must allow empty.
export function stripAnsi(s) {
  return String(s).replace(/\x1b\[[0-9;]*[A-Za-z]/g, '');
}

/** Normalise the shell's `\r\r\n` / `\r\n` endings into `\n`. */
export function normaliseNewlines(s) {
  return String(s).replace(/\r\r\n/g, '\n').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

/** True for the `: command not found` reply that an unknown command produces. */
/**
 * The dongle talking to itself — never a reply, whichever gap it lands in.
 *
 * `<info>`/`<warning>` lines are the logger's. But the log backend also prints
 * UNPREFIXED: on a busy radio you get a bare `Logs dropped (3)` (the dongle's log
 * queue overflowing) and `ESB_ILLEGALMOD: dropped promiscuous frame …`. Those were
 * being counted as content, so a gap holding nothing but `Logs dropped (1)` looked
 * like a reply and got claimed — while the real answer sat in a later gap. Raw
 * capture: `options show` returned its whole options table, and the app reported
 * `Logs dropped (1)`.
 */
export function isChatter(line) {
  const t = String(line).trim();
  if (t === '') return true;
  if (/^<(info|warning)>/.test(t)) return true;          // the logger's own lines
  if (/^Logs dropped \(\d+\)$/.test(t)) return true;    // log queue overflowed
  if (/^ESB_ILLEGALMOD\b/.test(t)) return true;           // dropped radio frames
  if (/^LOGITACKER_[A-Z0-9_]+:/.test(t)) return true;      // subsystem log, prefix lost
  return false;
}

export function isNotFound(text) {
  return /^\s*(\S+): command not found\s*$/m.test(text);
}

/**
 * Parse the `devices` listing.
 *
 * Captured shape — one line per device, then an indented continuation line:
 *
 *   AA:BB:CC:DD:08 'unknown name' keyboard: encrypted mouse: no
 *   \tclass: Logitech Unifying compatible device WPID: 0x0000 dongle WPID: 0x0000
 *
 * Field order is not assumed: the address and the quoted name are matched, the
 * kind is whichever of keyboard/mouse appears, and the flags are read as
 * presence patterns ("encrypted" appears with no value, "mouse: no" does).
 */
export function parseDevices(text) {
  const out = [];
  let current = null;
  for (const rawLine of normaliseNewlines(stripAnsi(text)).split('\n')) {
    const line = rawLine.replace(/\t/g, ' ').trimEnd();
    const m = line.match(/^\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){4})\s+'(.*?)'\s*(.*)$/);
    if (m) {
      current = {
        addr: m[1],
        name: m[2],
        kind: /\bkeyboard\b/i.test(m[3]) ? 'keyboard' : /\bmouse\b/i.test(m[3]) ? 'mouse' : 'unknown',
        encrypted: /\bencrypted\b/i.test(m[3]),
        isMouse: /\bmouse:\s*yes\b/i.test(m[3]),
        wpid: null,
        dongleWpid: null,
        cls: null,
        raw: line.trim(),
        detail: [],
      };
      out.push(current);
      continue;
    }
    if (current && /^\s+(class|WPID|dongle WPID)/i.test(rawLine)) {
      const w = line.match(/WPID:\s*(0x[0-9A-Fa-f]+|\?)/g) || [];
      // The firmware prints "class: %s device WPID: %s dongle WPID: %s", so a
      // trailing " device" is sentence text, not part of the class name.
      const cls = line.match(/class:\s*([^]*?)(?=\s+WPID:|$)/);
      if (cls) current.cls = cls[1].trim().replace(/\s+device$/, '');
      const wpids = line.match(/WPID:\s*(0x[0-9A-Fa-f]+|\?)/gi) || [];
      if (wpids[0]) current.wpid = wpids[0].replace(/.*:\s*/, '');
      if (wpids[1]) current.dongleWpid = wpids[1].replace(/.*:\s*/, '');
      current.detail.push(line.trim());
    }
  }
  return out;
}

/** Key/value pairs out of a `script -h` style help block (`  name  :text`). */
export function parseHelp(text) {
  const subs = [];
  let inSubs = false;
  for (const line of normaliseNewlines(stripAnsi(text)).split('\n')) {
    if (/^\s*Subcommands:\s*$/.test(line)) { inSubs = true; continue; }
    if (!inSubs) continue;
    const m = line.match(/^\s*([a-z_]+)\s*:(.*)$/i);
    if (m) subs.push({ name: m[1], help: m[2].trim() });
  }
  return subs;
}

/**
 * Splits a byte stream into prompt-delimited records.
 *
 * A record is everything printed after a prompt up to the next prompt — i.e. the
 * echo of one command plus its reply, with any async `<info>` lines interleaved.
 */
export class PromptSplitter {
  constructor() {
    this.buf = '';
    this.mode = null;
    this._pending = '';   // text seen since the last prompt
    this._seenPrompt = false;
  }

  /** Feed raw text; returns an array of completed records. */
  push(text) {
    this.buf += text;
    const records = [];
    let last = 0;
    PROMPT_RE.lastIndex = 0;
    let m;
    while ((m = PROMPT_RE.exec(this.buf)) !== null) {
      const between = this.buf.slice(last, m.index);
      if (this._seenPrompt) {
        records.push(this._close(between, this.mode));
      }
      // Anything before the very first prompt is tty echo / banner noise, never a
      // reply — and emitting it as a record would shift every later reply by one,
      // which is the bug class this whole file exists to avoid. Dropped on purpose;
      // ready() re-syncs by sending a bare newline.
      this.mode = m[1].trim();
      this._seenPrompt = true;
      // Count them: waiting for "a prompt" is how sync works, and a bare newline
      // produces an EMPTY gap (echo + prompt), which is correctly not a reply.
      this.prompts = (this.prompts || 0) + 1;
      last = m.index + m[0].length;
    }
    this.buf = this.buf.slice(last);
    return records;
  }

  _close(text, mode) {
    const clean = normaliseNewlines(stripAnsi(text));
    const lines = clean.split('\n');
    // Drop the echoed command: the shell prints back what it was sent.
    return { text: clean, lines, mode, at: lines.length };
  }

  /** Text received since the last prompt (the in-flight record). */
  get pending() { return this.buf; }
  get sawPrompt() { return this._seenPrompt; }
}

/**
 * A command runner over an attached transport.
 *
 * `send` is injected (bytes -> Promise) so tests can drive it with no device.
 */
export class LogitackerSession {
  constructor({ send, onMode, onEvent, onOutput, timeoutMs = 4000 } = {}) {
    this.send = send;
    this.onMode = onMode || (() => {});
    this.onEvent = onEvent || (() => {});
    this.onOutput = onOutput || (() => {});
    this.timeoutMs = timeoutMs;
    // The shell can take several seconds to emit its first prompt after the port
    // opens, and that is the only thing that tells us the link is really alive.
    this.syncTimeoutMs = Math.max(timeoutMs * 2, 8000);
    this.splitter = new PromptSplitter();
    this.queue = [];          // completed records not yet claimed
    this._waiters = [];       // { resolve } waiting for the next record
    this.mode = null;
    this.log = [];            // every command sent, for the UI
  }

  /** Wire to a UsbTransport's `onData`. */
  feed(bytes) {
    const text = new TextDecoder().decode(bytes);
    if (this.onOutput) this.onOutput(text);
    const records = this.splitter.push(text);
    // The mode lives in the PROMPT, so track it the moment a prompt arrives — not
    // when a reply happens to be attributed to one. A prompt followed by nothing
    // but echo emits no record at all (that is the point of the empty-gap rule),
    // and the mode still has to be known.
    if (this.splitter.mode && this.splitter.mode !== this.mode) {
      this.mode = this.splitter.mode;
      this.onMode(this.mode);
    }
    for (const rec of records) {
      for (const ev of this._events(rec)) this.onEvent(ev);
      // An info-only gap is asynchronous chatter, not a reply. Queueing it would
      // hand every later command the PREVIOUS record — the off-by-one that makes
      // a parser look like it works while reporting the wrong thing forever.
      if (!this._claimable(rec)) continue;
      const w = this._waiters.shift();
      if (w) w.resolve(rec); else this.queue.push(rec);
    }
  }

  /**
   * True if a record holds anything that could be a reply.
   *
   * Chatter is not content: <info> and <warning> lines are the shell talking to
   * itself. Nor is the echoed command — it appears in every gap, so counting it
   * would let a gap holding nothing but our own echo and some warnings satisfy a
   * command, and the reply to the NEXT command would then be attributed to this
   * one. That off-by-one is the bug class this file exists to prevent, and a slow
   * honest timeout is much cheaper than a wrong answer.
   */
  _claimable(rec) {
    const echo = (this._inFlight || '').trim();
    return rec.text.split('\n').some((l) => {
      const t = l.trim();
      if (isChatter(t)) return false;
      if (echo && t === echo) return false;
      return true;
    });
  }

  _events(rec) {
    return rec.text.split('\n')
      .filter((l) => isChatter(l) && l.trim() !== '')
      .map((l) => l.replace(/^\s*<(?:info|warning)>\s?/, '').trim());
  }

  /** The body of a record: the reply, with echo and <info> lines removed. */
  _body(rec, cmd) {
    const lines = rec.text.split('\n');
    const out = [];
    let echoStripped = false;
    for (const line of lines) {
      if (isChatter(line)) continue;
      if (!echoStripped && line.trim() === '') continue;          // leading blank lines
      // The shell echoes what it was sent; that first non-blank line is our own
      // command coming back, not part of the reply.
      if (!echoStripped && cmd && line.trim() === cmd.trim()) { echoStripped = true; continue; }
      echoStripped = true;
      out.push(line);
    }
    return out.join('\n').trim();
  }

  _nextRecord(timeoutMs) {
    // Drop any queued chatter first; see _claimable().
    while (this.queue.length && !this._claimable(this.queue[0])) this.queue.shift();
    if (this.queue.length) return Promise.resolve(this.queue.shift());
    return new Promise((resolve, reject) => {
      // Track the waiter by IDENTITY. Matching on the promise's `resolve` never
      // matches, because the waiter stores a WRAPPER around it — so the timed-out
      // waiter was never removed, the list grew, and every later reply was handed
      // to a dead waiter. One timeout broke the session for good. (Found by
      // printing _waiters.length: 11 and climbing, with every command timing out.)
      const waiter = { resolve: (rec) => { clearTimeout(timer); resolve(rec); } };
      const timer = setTimeout(() => {
        const i = this._waiters.indexOf(waiter);
        if (i >= 0) this._waiters.splice(i, 1);
        reject(new Error(`LOGITacker: no reply to "${this._inFlight || '?'}" within ${timeoutMs}ms`));
      }, timeoutMs);
      this._waiters.push(waiter);
    });
  }

  /** Wait until another prompt appears, or give up. Polling keeps this obvious. */
  _waitPrompt(baseline, timeoutMs) {
    if ((this.splitter.prompts || 0) > baseline) return Promise.resolve(true);
    return new Promise((resolve) => {
      const deadline = Date.now() + timeoutMs;
      let timer;
      const tick = () => {
        if ((this.splitter.prompts || 0) > baseline) { clearTimeout(timer); resolve(true); return; }
        if (Date.now() >= deadline) { clearTimeout(timer); resolve(false); return; }
        timer = setTimeout(tick, 100);
      };
      timer = setTimeout(tick, 100);
    });
  }

  /**
   * Sync the shell to a known state: get it to print a prompt, which is its only
   * reliable liveness signal.
   *
   * Deliberately NOT `run('')`. A bare newline answers with an echo and a prompt
   * and nothing else, so the gap between prompts is empty — and an empty gap is
   * correctly not a reply (that rule is what stops replies being attributed to
   * the wrong command). Waiting for the prompt sidesteps that entirely, and the
   * newline is resent because the shell can swallow one across a fresh open.
   *
   * Bytes already in the buffer on connect are unattributable and the FIRST
   * prompt is the splitter's boundary, so the baseline is taken, not assumed.
   */
  async ready(timeoutMs = this.syncTimeoutMs) {
    const baseline = this.splitter.prompts || 0;
    const deadline = Date.now() + timeoutMs;
    let attempts = 0;
    while (Date.now() < deadline) {
      attempts++;
      await this.send(new TextEncoder().encode('\r\n'));
      const slice = Math.min(2000, Math.max(400, deadline - Date.now()));
      if (await this._waitPrompt(baseline, slice)) {
        return { ok: true, mode: this.mode, attempts, prompts: this.splitter.prompts || 0 };
      }
    }
    return { ok: false, mode: this.mode, attempts, prompts: this.splitter.prompts || 0 };
  }

  /**
   * Send one command line and return its reply.
   * Resolves { cmd, body, lines, mode, notFound, timedOut }.
   */
  async run(cmd, { timeoutMs = this.timeoutMs } = {}) {
    const line = String(cmd).trim();
    this._inFlight = line;
    this.log.push(line);
    await this.send(new TextEncoder().encode(line + '\r\n'));
    let rec;
    try {
      rec = await this._nextRecord(timeoutMs);
    } catch (e) {
      return { cmd: line, body: '', lines: [], mode: this.mode, notFound: false, timedOut: true, error: e.message };
    } finally {
      this._inFlight = null;
    }
    const body = this._body(rec, line);
    return {
      cmd: line,
      body,
      lines: body ? body.split('\n') : [],
      mode: rec.mode || this.mode,
      notFound: isNotFound(body),
      timedOut: false,
    };
  }

  // ── typed commands (verified against the live shell) ───────────────────────
  async devices(opts) {
    const r = await this.run('devices', opts);
    return { ...r, devices: parseDevices(r.body) };
  }

  async scriptHelp(opts) {
    const r = await this.run('script -h', opts);
    return { ...r, subcommands: parseHelp(r.body) };
  }

  /** Append "type this text" to the injection script. */
  scriptString(text, opts) { return this.run(`script string ${quoteArg(text)}`, opts); }
  /** Append a key combination, e.g. press('GUI','r') or press('ENTER'). */
  scriptPress(keys, opts) {
    const args = Array.isArray(keys) ? keys : [keys];
    return this.run(`script press ${args.map(quoteArg).join(' ')}`, opts);
  }
  scriptDelay(ms, opts) { return this.run(`script delay ${Number(ms) | 0}`, opts); }
  scriptShow(opts) { return this.run('script show', opts); }
  injectTarget(addr, opts) { return this.run('inject target ' + addr, opts); }
  injectExecute(opts) { return this.run('inject execute', opts); }

  scriptClear(opts) { return this.run('script clear', opts); }
  /** Names are quoted because the shell refuses to overwrite an existing one. */
  scriptStore(name, opts) {
    return this.run(name ? `script store ${quoteArg(name)}` : 'script store', opts);
  }
  scriptLoad(name, opts) { return this.run(`script load ${quoteArg(name)}`, opts); }
  scriptList(opts) { return this.run('script list', opts); }
  scriptRemove(name, opts) { return this.run(`script remove ${quoteArg(name)}`, opts); }

  /** Is a command one this shell actually has? (Probe, never assume.) */
  async probe(cmd, opts) {
    const r = await this.run(cmd, opts);
    return { ...r, known: !r.notFound && !r.timedOut };
  }
}

/**
 * Quote an argument for the shell.
 *
 * UNVERIFIED against the device: the shell's own quoting rules for `script
 * string` have not been exercised on air yet. Double-quoting is the safe default
 * (spaces are otherwise split into separate parameters); if the device turns out
 * to want raw text, that is a one-line change here and nothing else moves.
 */
export function quoteArg(s) {
  const str = String(s);
  if (/^[A-Za-z0-9_.:-]+$/.test(str)) return str;
  return '"' + str.replace(/(["\\])/g, '\\$1') + '"';
}

// ─────────────────────────────────────────────────────────────────────────────
// The command vocabulary, so nobody has to know it by heart.
//
// Source: LOGITacker's own documentation (the firmware's README), which lists
// these verbatim, plus `script` as printed by the device itself (`script -h`).
// `script`'s subcommands were confirmed on the live shell; everything else here
// is documented, not observed, so the UI must not claim more than it knows.
//
// NOTE: the shell has NO `help` and NO `?`. Unknown commands answer
// `<cmd>: command not found`, and under RF load even that can be dropped.
// ─────────────────────────────────────────────────────────────────────────────

export const LOGITACKER_COMMANDS = [
  { group: 'Devices — what it can hear', cmd: 'devices', desc: 'List the wireless devices heard so far' },
  { group: 'Devices — what it can hear', cmd: 'devices storage list', desc: 'Devices saved on the dongle' },
  { group: 'Devices — what it can hear', cmd: 'devices storage save <address>', desc: 'Save a device to the dongle' },
  { group: 'Devices — what it can hear', cmd: 'devices storage load <address>', desc: 'Load a saved device' },

  { group: 'Script — build the keystrokes', cmd: 'script', desc: 'Show the script commands (help)' },
  { group: 'Script — build the keystrokes', cmd: 'script clear', desc: 'Start a new, empty script' },
  { group: 'Script — build the keystrokes', cmd: 'script undo', desc: 'Remove the last step' },
  { group: 'Script — build the keystrokes', cmd: 'script show', desc: 'Show the script built so far' },
  { group: 'Script — build the keystrokes', cmd: 'script string "<text>"', desc: 'Type text (follows keyboard layout)' },
  { group: 'Script — build the keystrokes', cmd: 'script altstring "<text>"', desc: 'Type text as NUMPAD codes (layout-independent, Windows)' },
  { group: 'Script — build the keystrokes', cmd: 'script press <KEY> [<KEY>]', desc: 'Press keys together, e.g. CTRL A' },
  { group: 'Script — build the keystrokes', cmd: 'script delay <ms>', desc: 'Wait, in milliseconds' },
  { group: 'Script — build the keystrokes', cmd: 'script store "<name>"', desc: 'Save the script to the dongle' },
  { group: 'Script — build the keystrokes', cmd: 'script load <name>', desc: 'Load a saved script' },
  { group: 'Script — build the keystrokes', cmd: 'script list', desc: 'List scripts saved on the dongle' },
  { group: 'Script — build the keystrokes', cmd: 'script remove "<name>"', desc: 'Delete a saved script' },

  { group: 'Inject — fire a script', cmd: 'inject target <address>', desc: 'Aim the dongle at a device' },
  { group: 'Inject — fire a script', cmd: 'inject execute', desc: 'Fire the loaded script at that target' },

  { group: 'Pairing', cmd: 'pair sniff run', desc: 'Sniff a device pairing to capture its link key' },

  { group: 'Settings', cmd: 'options show', desc: 'Show the current settings' },
  { group: 'Settings', cmd: 'options inject language us', desc: 'US keyboard layout (QWERTY)' },
  { group: 'Settings', cmd: 'options inject default-script "<name>"', desc: 'Script to load on boot' },
  { group: 'Settings', cmd: 'options inject onsuccess continue', desc: 'After a good injection: stay in injection mode' },
  { group: 'Settings', cmd: 'options inject onsuccess discover', desc: 'After a good injection: back to discover' },
  { group: 'Settings', cmd: 'options inject onfail', desc: 'What to do after a failed injection' },
  { group: 'Settings', cmd: 'options passive-enum pass-through-keyboard on', desc: 'Mirror sniffed keystrokes to USB' },
  { group: 'Settings', cmd: 'options passive-enum pass-through-mouse on', desc: 'Mirror sniffed mouse to USB' },
  { group: 'Settings', cmd: 'options store', desc: 'Save settings so they survive a re-plug' },
];

// Key names `script press` accepts — copied from the documented list. The
// everyday ones lead, so the dropdown is usable without scrolling.
export const PRESS_KEYS = [
  'RETURN', 'ENTER', 'ESC', 'TAB', 'SPACE', 'BACKSPACE', 'DELETE', 'INSERT',
  'UP', 'DOWN', 'LEFT', 'RIGHT', 'HOME', 'END', 'PAGEUP', 'PAGEDOWN',
  'CAPSLOCK', 'NUMLOCK', 'PRINTSCREEN', 'SCROLLLOCK', 'PAUSE', 'MENU',
  'CTRL', 'SHIFT', 'ALT', 'GUI', 'LEFTCTRL', 'LEFTSHIFT', 'LEFTALT', 'LEFTMETA',
  ...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split(''),
  ...'1234567890'.split(''),
  ...Array.from({ length: 12 }, (_, i) => 'F' + (i + 1)),
];

// Whole scripts, ready to send. Each starts with `script clear` — the shell
// APPENDS to the current script, so without a clear you inherit whatever was
// there. `{text}` comes from the text box in the card; `{text|id}` is a default.
export const PREBUILT_SCRIPTS = [
  {
    id: 'calc-win',
    name: 'Calculator — Windows',
    desc: "The firmware docs' own example: opens Run, retypes the command as NUMPAD codes, launches calc.",
    steps: ['script clear', 'script press NUMLOCK', 'script press GUI F1', 'script delay 500',
            'script altstring "cmd.exe"', 'script press CTRL A', 'script press CTRL X',
            'script press ALT F4', 'script delay 200', 'script press GUI', 'script delay 200',
            'script press CTRL V', 'script press RETURN', 'script delay 500',
            'script altstring "calc.exe"', 'script press RETURN'],
  },
  {
    id: 'notepad-win',
    name: 'Notepad — Windows, via Run',
    desc: 'GUI+R, type the program name, Enter.',
    steps: ['script clear', 'script press GUI R', 'script delay 700', 'script string "notepad.exe"',
            'script press RETURN'],
  },
  {
    id: 'type-line',
    name: 'Type this text, then Enter',
    desc: 'Types whatever is in the text box, then presses Enter. Uses the current keyboard layout.',
    steps: ['script clear', 'script string "{text}"', 'script press RETURN'],
  },
  {
    id: 'numpad-type',
    name: 'Type text as NUMPAD codes',
    desc: 'Layout-independent typing (Windows). Slower, but survives a foreign layout or a letter blacklist.',
    steps: ['script clear', 'script press NUMLOCK', 'script delay 300', 'script altstring "{text}"',
            'script press RETURN'],
  },
  {
    id: 'linux-term',
    name: 'Terminal + command — Linux',
    desc: 'Ctrl+Alt+T, wait for the window, type the command, Enter.',
    steps: ['script clear', 'script press CTRL ALT T', 'script delay 900', 'script string "{text|id}"',
            'script press RETURN'],
  },
  {
    id: 'hello-test',
    name: 'Test: type "hello"',
    desc: 'Harmless smoke test — proves the injection path works end to end before you fire anything real.',
    steps: ['script clear', 'script string "hello from the dongle"', 'script press RETURN'],
  },
];
