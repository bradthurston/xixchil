// capture.js — the Capture stage.
//
// Drives the device's sniffer, pulls the PSRAM buffer down over the link, and
// writes a pcap to the phone. The device persists nothing, so this module is
// where a capture actually becomes a file.
//
// The shape of the exchange (see firmware/src/main.cpp):
//
//   CAPTURE_START {channel, duration_ms, snaplen}  -> {started, t0_us, buf_bytes}
//   ... device sniffs into PSRAM, then auto-stops and emits `capture_done` ...
//   CAPTURE_STOP                                   -> {frames, dropped, bytes, ...}
//   CAPTURE_GET {offset, count}                    -> N x FT_PCAP frames, then
//                                                     {sent, next_offset, done}
//
// CAPTURE_GET is a pull, not a stream. The device never pushes frames at the
// phone unbidden — see the coexistence note at the top of main.cpp for why the
// architecture is "capture, then sync" rather than "stream while sniffing".

import { PcapWriter } from './pcap.js';
import { bytesToBase64 } from './transport.js';

function filesystem() {
  const p = window.Capacitor?.Plugins?.Filesystem;
  if (!p) throw new Error('Filesystem plugin not available (not running in the app?)');
  return p;
}

function timestampName() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `capture-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}`
       + `-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}.pcap`;
}

export class CaptureSession {
  constructor({ request, log, onProgress } = {}) {
    this.request = request;
    this.log = log || (() => {});
    this.onProgress = onProgress || (() => {});

    this.running = false;
    this.channel = 1;
    this.durationMs = 10000;
    this.stats = null;      // last CAPTURE_STOP / capture_done payload
    this.startInfo = null;  // last CAPTURE_START payload

    this.t0Us = null;       // device µs at capture start
    this.t0WallMs = null;   // phone wall clock when that reply landed
    this.writer = null;     // PcapWriter for the current sync
    this.saved = null;      // {uri, directory, path, bytes} once written

    // ── continuous mode ──────────────────────────────────────────────
    this.continuousRunning = false;
    this.continuousChannel = 1;
    this.continuousStartWallMs = null;  // when the continuous session began
    this.continuousPackets = 0;         // total across all segments
    this.continuousSegments = 0;
    this._continuousDry = false;        // true while syncing between segments
  }

  get hasData() {
    return !!this.writer && this.writer.packets > 0;
  }

  async start({ channel = 1, durationMs = 10000, snaplen = 512 } = {}) {
    if (this.running) throw new Error('capture already running');

    const resp = await this.request('CAPTURE_START', {
      channel, duration_ms: durationMs, snaplen,
    }, { timeoutMs: 10000 });
    if (!resp || !resp.ok) throw new Error(resp?.error || 'capture start failed');

    // Sample the wall clock HERE, immediately after the reply landed, and pair
    // it with the device's t0 from that same reply. Every timestamp the pcap
    // writer produces hangs off this one pairing — which is why the firmware
    // bothers to return t0_us at all.
    this.t0WallMs = Date.now();
    this.t0Us = Number(resp.t0_us);

    this.startInfo = resp;
    this.channel = resp.channel ?? channel;
    this.durationMs = resp.duration_ms ?? durationMs;
    this.running = true;

    // A new capture invalidates the previous file. Say so rather than leaving
    // stale stats on screen next to fresh ones.
    this.stats = null;
    this.writer = null;
    this.saved = null;

    return resp;
  }

  async stop() {
    if (!this.running) return this.stats;
    const resp = await this.request('CAPTURE_STOP', undefined, { timeoutMs: 10000 });
    this.running = false;
    this.stats = resp || null;
    return resp;
  }

  /** The device auto-stopped on its own duration and said so. */
  onCaptureDone(payload) {
    this.running = false;
    this.stats = payload || null;
    // If in continuous mode, chain the next segment
    if (this.continuousRunning && !this._continuousDry) {
      this._continuousStep().catch((err) => {
        this.log('err', `continuous: ${err.message}`);
        this.continuousRunning = false;
      });
    }
  }

  // ── continuous capture ───────────────────────────────────────────

  /** Start a continuous capture session. Loops start→wait→sync→start
   *  until stopContinuous() is called. Frames from all segments
   *  accumulate into one PcapWriter. */
  async startContinuous({ channel = 1, durationMs = 10000, snaplen = 512 } = {}) {
    if (this.continuousRunning) throw new Error('continuous already running');
    if (this.running) throw new Error('capture already running');

    this.continuousRunning = true;
    this.continuousChannel = channel;
    this.continuousStartWallMs = Date.now();
    this.continuousPackets = 0;
    this.continuousSegments = 0;
    this._continuousDry = false;
    this.writer = null;
    this.saved = null;

    // Create a single writer that spans all segments. Anchor gets
    // updated per segment before the first frame arrives.
    this.writer = new PcapWriter({});

    const resp = await this._startSegment({ channel, durationMs, snaplen });
    return resp;
  }

  /** Internal: send CAPTURE_START for one segment. */
  async _startSegment({ channel, durationMs, snaplen } = {}) {
    const resp = await this.request('CAPTURE_START', {
      channel, duration_ms: durationMs, snaplen,
    }, { timeoutMs: 10000 });
    if (!resp || !resp.ok) throw new Error(resp?.error || 'capture start failed');

    this.t0WallMs = Date.now();
    this.t0Us = Number(resp.t0_us);
    this.startInfo = resp;
    this.channel = resp.channel ?? channel;
    this.durationMs = resp.duration_ms ?? durationMs;
    this.running = true;
    this.stats = null;
    return resp;
  }

  /** Internal: pull the just-finished segment's frames into the
   *  persistent writer, then start the next segment. Called from
   *  onCaptureDone via _continuousStep. */
  async _continuousStep() {
    this._continuousDry = true;

    // Update the writer's anchor for this segment's timestamps
    this.writer.updateAnchor(this.t0Us, this.t0WallMs);

    // Pull all frames for this segment
    let offset = 0;
    let batches = 0;
    for (;;) {
      const resp = await this.request('CAPTURE_GET', { offset, count: 128 },
        { timeoutMs: 30000 });
      if (!resp || !resp.ok) throw new Error(resp?.error || 'capture_get failed');
      offset = resp.next_offset ?? offset;
      if (resp.done) break;
      if (!resp.sent) break;
      if (++batches > 100000) throw new Error('capture_get did not terminate');
    }

    this.continuousPackets = this.writer?.packets ?? 0;
    this.continuousSegments++;

    // Check if we should keep going (user may have called stopContinuous
    // during the sync, which sets continuousRunning = false)
    if (!this.continuousRunning) {
      this._continuousDry = false;
      return;
    }

    this._continuousDry = false;
    // Start the next segment
    const resp = await this._startSegment({
      channel: this.continuousChannel,
      durationMs: this.durationMs,
    });
    if (!resp || !resp.ok) throw new Error(resp?.error || 'continuous segment failed');
  }

  /** Stop the continuous session. Finishes the current segment's sync
   *  (if any), saves the accumulated pcap, and returns the save result. */
  async stopContinuous() {
    if (!this.continuousRunning) throw new Error('not running');

    // Signal the loop to stop — this prevents _continuousStep from
    // starting another segment after it finishes syncing.
    this.continuousRunning = false;

    // If a capture is currently running on the board, stop it
    if (this.running) {
      await this.request('CAPTURE_STOP', undefined, { timeoutMs: 10000 });
      this.running = false;
    }

    // If we were mid-sync (_continuousDry), _continuousStep already
    // handled the pull and won't restart. Wait a tick for it.
    if (this._continuousDry) {
      await new Promise((r) => setTimeout(r, 500));
    }

    // Save if we have data
    if (this.writer && this.writer.packets > 0) {
      const saved = await this.save();
      return saved;
    }
    return null;
  }

  /** Feed an FT_PCAP frame from the link into the file being assembled. */
  onPcapChunk(chunk) {
    if (this.writer) this.writer.add(chunk);
  }

  /**
   * Pull the buffered frames down and assemble the pcap.
   *
   * Loops CAPTURE_GET until the device reports `done`. The device walks the
   * buffer from a byte offset, so this resumes exactly where the last batch
   * stopped and needs no frame index on either side.
   */
  async sync({ batch = 128, onProgress } = {}) {
    if (this.running) throw new Error('stop the capture first');

    const w = new PcapWriter({ t0Us: this.t0Us, t0WallMs: this.t0WallMs });
    this.writer = w;
    this.saved = null;

    const progress = onProgress || this.onProgress;
    let offset = 0;
    let total = null;
    let batches = 0;

    for (;;) {
      const resp = await this.request('CAPTURE_GET', { offset, count: batch },
        { timeoutMs: 30000 });
      if (!resp || !resp.ok) throw new Error(resp?.error || 'capture_get failed');

      if (typeof resp.total_bytes === 'number') total = resp.total_bytes;
      offset = resp.next_offset ?? offset;
      progress({ packets: w.packets, offset, total });

      if (resp.done) break;
      // No forward progress means the device has nothing more to give. Stop
      // rather than spin a request loop against it.
      if (!resp.sent) break;
      if (++batches > 100000) throw new Error('capture_get did not terminate');
    }

    this.log('ev', `synced ${w.packets} frames (${w.bytes} bytes) in ${batches + 1} batch(es)`);
    return w;
  }

  /** What the operator should be told about the assembled file. */
  summary() {
    const w = this.writer;
    return {
      packets: w ? w.packets : 0,
      bytes: w ? w.bytes : 0,
      payloadBytes: w ? w.payloadBytes : 0,
      timed: w ? w.timed : 0,
      untimed: w ? w.untimed : 0,
      spanMs: w ? w.spanMs() : null,
      deviceFrames: this.stats?.frames ?? null,
      deviceDropped: this.stats?.dropped ?? null,
    };
  }

  /**
   * Write the assembled pcap to the phone.
   *
   * Documents is the public folder, so the file can be pulled off the phone
   * without root or adb — which is the entire reason this is a file on a phone
   * and not a buffer on a microcontroller. On Android 11+ an app may only touch
   * files it created in a public directory, which is exactly our case.
   *
   * If the platform refuses anyway, fall back to app-private storage. A capture
   * you can only reach over adb still beats losing the capture.
   */
  async save({ name } = {}) {
    if (!this.hasData) throw new Error('nothing captured to save');

    const bytes = this.writer.toBytes();
    const filename = name || timestampName();
    const data = bytesToBase64(bytes);

    const attempts = [
      { directory: 'DOCUMENTS', path: `RadioConsole/${filename}` },
      { directory: 'EXTERNAL_STORAGE', path: `RadioConsole/${filename}` },
      { directory: 'DATA', path: filename },
    ];

    let lastErr = null;
    for (const a of attempts) {
      try {
        const res = await filesystem().writeFile({
          path: a.path,
          data,
          directory: a.directory,
          recursive: true,
        });
        this.saved = {
          uri: res?.uri || `${a.directory}/${a.path}`,
          directory: a.directory,
          path: a.path,
          bytes: bytes.length,
          packets: this.writer.packets,
        };
        return this.saved;
      } catch (e) {
        lastErr = e;
      }
    }
    throw new Error('could not write the pcap: ' + (lastErr?.message || 'unknown error'));
  }
}
