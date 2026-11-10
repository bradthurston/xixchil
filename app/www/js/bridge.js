// bridge.js — talking to the GPU box that does the searching.
//
// A phone can extract a handshake but it cannot search a real wordlist; that is
// a GPU job. This is the client for the crack bridge: hand it a .22000, get a
// job id, poll until the search finishes, read the passphrase back.
//
// ── WHY THIS DOES NOT USE fetch() ───────────────────────────────────────────
// The app runs in a WebView served from https://localhost. The bridge is plain
// HTTP on the LAN, at a different origin, and it sends no CORS headers — so an
// ordinary fetch is blocked by the browser before it leaves. Capacitor's native
// HTTP does the request outside the WebView, where no same-origin policy
// applies. That is the whole reason this file exists in this shape rather than
// as three lines of fetch.
//
// The bridge is token-gated via an X-Token header, which is itself the reason a
// plain fetch would need a preflight. Native HTTP sidesteps that too.

const BOUNDARY = '----RadioConsoleBridgeBoundary';

/**
 * Build a multipart/form-data body by hand.
 *
 * The bridge takes a file upload, and there is no FormData in a native request,
 * so the body is assembled as text. The CRLFs are not optional — a multipart
 * body with bare newlines is rejected by the server's parser with a message
 * that does not mention newlines.
 */
function multipartBody({ filename, content, fields }) {
  const parts = [];
  parts.push(
    `--${BOUNDARY}\r\n` +
    `Content-Disposition: form-data; name="file"; filename="${filename}"\r\n` +
    'Content-Type: application/octet-stream\r\n\r\n' +
    content + '\r\n',
  );
  for (const [name, value] of Object.entries(fields || {})) {
    parts.push(
      `--${BOUNDARY}\r\n` +
      `Content-Disposition: form-data; name="${name}"\r\n\r\n` +
      String(value) + '\r\n',
    );
  }
  parts.push(`--${BOUNDARY}--\r\n`);
  return parts.join('');
}

/** Parse a JSON response body, whether it arrived as text or already as an object. */
function asJson(res) {
  const d = res?.data;
  if (d == null) return null;
  if (typeof d === 'object') return d;
  try { return JSON.parse(d); } catch { return null; }
}

export class CrackBridge {
  constructor({ baseUrl, token, timeoutMs = 15000 } = {}) {
    // Trailing slash on the base would double up in the path.
    this.baseUrl = String(baseUrl || '').replace(/\/+$/, '');
    this.token = token || '';
    this.timeoutMs = timeoutMs;
  }

  get configured() {
    return !!this.baseUrl;
  }

  /** The native HTTP bridge, when the app is running on a device. */
  get http() {
    // Guarded because this module is also loaded outside a browser (the test
    // harness drives the real bridge from node), where window does not exist.
    if (typeof window === 'undefined') return null;
    return window.Capacitor?.Plugins?.CapacitorHttp || null;
  }

  /** One request. Uses native HTTP when present, fetch otherwise (browser dev). */
  async request(method, path, { body, headers = {}, raw = false } = {}) {
    const url = this.baseUrl + path;
    const h = { ...headers };
    if (this.token) h['X-Token'] = this.token;

    if (this.http) {
      const res = await this.http.request({
        url,
        method,
        headers: h,
        data: body,
        connectTimeout: this.timeoutMs,
        readTimeout: this.timeoutMs,
      });
      return res;
    }

    // Browser fallback — for `npm run build`-time checks on a desktop. This is
    // the path that CORS blocks against a real bridge; it is here so the module
    // can be exercised without a phone, not as the production route.
    const res = await fetch(url, { method, headers: h, body });
    const text = await res.text();
    return { status: res.status, data: raw ? text : text };
  }

  /** Is the bridge up, and what can it do? No auth needed. */
  async health() {
    if (!this.configured) throw new Error('no bridge URL set');
    const res = await this.request('GET', '/health');
    const j = asJson(res);
    if (!j || !j.ok) throw new Error(`bridge unhealthy (HTTP ${res.status})`);
    return j;
  }

  /** Wordlists the bridge can search. Needs the token. */
  async wordlists() {
    const res = await this.request('GET', '/wordlists');
    if (res.status === 401) throw new Error('bridge rejected the token (401)');
    const j = asJson(res);
    if (!j) throw new Error(`bad wordlist response (HTTP ${res.status})`);
    return j.wordlists || j;
  }

  /**
   * Submit a .22000 for cracking.
   *
   * Returns the job id. The bridge queues it — exactly one hashcat runs at a
   * time, so a second submission waits rather than fighting the first for the
   * GPU.
   */
  async submit({ hashes, wordlist = 'rockyou.txt', rules = 'none', filename = 'handshake.22000' }) {
    if (!hashes || !hashes.includes('WPA*')) {
      throw new Error('nothing to submit — no WPA* line');
    }
    const body = multipartBody({
      filename,
      content: hashes,
      fields: { wordlist, rules },
    });
    const res = await this.request('POST', '/crack', {
      body,
      headers: { 'Content-Type': `multipart/form-data; boundary=${BOUNDARY}` },
    });

    if (res.status === 401) throw new Error('bridge rejected the token (401)');
    const j = asJson(res);
    if (res.status !== 202 || !j?.job_id) {
      throw new Error(j?.detail || `submit failed (HTTP ${res.status})`);
    }
    return j.job_id;
  }

  /** One status reading. */
  async status(jobId) {
    const res = await this.request('GET', `/jobs/${jobId}`);
    if (res.status === 404) throw new Error('no such job on the bridge');
    const j = asJson(res);
    if (!j) throw new Error(`bad status response (HTTP ${res.status})`);
    return j;
  }

  /** Final state plus the passphrase, if it found one. */
  async result(jobId) {
    const res = await this.request('GET', `/jobs/${jobId}/result`);
    const j = asJson(res);
    if (!j) throw new Error(`bad result response (HTTP ${res.status})`);
    return j;
  }

  /**
   * Submit and wait for the answer.
   *
   * `onProgress` is called with each reading so the UI can show the search
   * moving. Terminal states are cracked / exhausted / failed; anything else
   * means keep waiting.
   *
   * The bridge decides the outcome from hashcat's outfile, not its exit code —
   * hashcat exits 0 for "ran fine, found nothing", which reads like success.
   * Nothing here second-guesses that; it reports what the bridge says.
   */
  async crack({ hashes, wordlist, rules, onProgress, pollMs = 2000, timeoutMs = 3600000 }) {
    const jobId = await this.submit({ hashes, wordlist, rules });
    const started = Date.now();
    let last = null;

    for (;;) {
      const s = await this.status(jobId);
      last = s;
      if (onProgress) onProgress(s);

      if (s.state === 'cracked') {
        const r = await this.result(jobId);
        return { jobId, state: 'cracked', password: r.password ?? s.password ?? null, job: r };
      }
      if (s.state === 'exhausted' || s.state === 'failed') {
        return { jobId, state: s.state, password: null, job: s };
      }
      if (Date.now() - started > timeoutMs) {
        return { jobId, state: 'timeout', password: null, job: last };
      }
      await new Promise((r) => setTimeout(r, pollMs));
    }
  }
}
