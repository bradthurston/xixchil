#!/usr/bin/env node
// verify_portal_dns.mjs — judge the FIRMWARE's DNS hijack encoder by its bytes.
//
// The point of this file: app/www/js/portal.js already builds this answer and
// tools/verify_portal.mjs already judges it with tshark. That proves the JS is
// right. It does NOT prove the C++ that actually runs on the board is right, and
// "it compiled" is not a claim about bytes — a build is evidence that the source
// parses, not that the encoder emits a legal DNS response.
//
// So: compile portal_dns.h itself (not a copy, not a mock) through a tiny host
// harness, feed it real queries, and put the answers in front of tshark. Two
// independent encoders (JS and C++) judged by an independent decoder is
// evidence; one encoder agreeing with its own test is not.
//
// Run:  node tools/verify_portal_dns.mjs
// Exit: 0 when every check passes, 1 otherwise. tshark and g++ must be present.

import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const HARNESS = join(here, 'host', 'portal_dns_host.cpp');
const HEADER  = join(root, 'firmware', 'src', 'portal_dns.h');

const OUR_IP = '192.168.4.1';
const TXID   = 0x4242;
const NAME   = 'connectivitycheck.gstatic.com';

let pass = 0, fail = 0;
const failures = [];

function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL ${name}${detail ? '  [' + detail + ']' : ''}`); }
}

// ── the probe results ───────────────────────────────────────────────────────
console.log('portal DNS hijack — firmware encoder judged by tshark');
console.log('');

if (!existsSync(HEADER)) { console.log(`FATAL: ${HEADER} missing`); process.exit(1); }

let haveTshark = true;
try { execFileSync('tshark', ['--version'], { stdio: 'ignore' }); } catch { haveTshark = false; }
check('tshark is available for the cross-check', haveTshark);
if (!haveTshark) { console.log('\nFAIL — no independent judge, so nothing else here would mean anything.'); process.exit(1); }

const work = mkdtempSync(join(tmpdir(), 'portal-dns-'));
const bin  = join(work, 'portal_dns_host');

let built = true;
try {
  execFileSync('g++', ['-O2', '-std=c++17', '-Wall', '-Wextra', '-o', bin, HARNESS], { stdio: 'pipe' });
} catch (e) {
  built = false;
  console.log('  g++ output: ' + String(e.stderr || e.message).trim());
}
check('the shipping encoder compiles standalone (no Arduino needed)', built);
if (!built) { console.log('\nFAIL — could not build the harness.'); process.exit(1); }

// ── build queries in JS, run them through the C++ encoder ───────────────────
function u16(n) { const b = Buffer.alloc(2); b.writeUInt16BE(n, 0); return b; }

function dnsName(name) {
  const out = [];
  for (const label of name.split('.').filter(Boolean)) {
    out.push(label.length);
    for (const ch of label) out.push(ch.charCodeAt(0));
  }
  out.push(0);
  return Buffer.from(out);
}

// A deliberately independent query builder. The JS encoder in portal.js builds
// queries too, but reusing it here would make the two sides share a bug.
function dnsQuery({ name = NAME, type = 1, id = TXID, rd = true, qdcount = 1, qclass = 1, raw = null }) {
  if (raw) return raw;
  const h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0);
  h.writeUInt16BE(rd ? 0x0100 : 0x0000, 2);
  h.writeUInt16BE(qdcount, 4);
  return Buffer.concat([h, dnsName(name), u16(type), u16(qclass)]);
}

function run(queryBuf, ip = OUR_IP) {
  const r = spawnSync(bin, [queryBuf.toString('hex'), ip], { encoding: 'utf8' });
  const out = (r.stdout || '').trim();
  if (out === 'REFUSED') return { refused: true, buf: null };
  if (!out) return { refused: true, buf: null, empty: true };
  return { refused: false, buf: Buffer.from(out, 'hex') };
}

const TYPE_A = 1, TYPE_AAAA = 28, TYPE_ANY = 255, TYPE_MX = 15;

// ── the pcap writer + tshark ────────────────────────────────────────────────
function checksum16(buf) {
  let sum = 0;
  for (let i = 0; i < buf.length; i += 2) sum += (buf[i] << 8) | (buf[i + 1] || 0);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}
function eth(dst, src, type, payload) {
  const d = Buffer.from(dst.split(':').map(h => parseInt(h, 16)));
  const s = Buffer.from(src.split(':').map(h => parseInt(h, 16)));
  const h = Buffer.alloc(14);
  d.copy(h, 0); s.copy(h, 6); h.writeUInt16BE(type, 12);
  return Buffer.concat([h, payload]);
}
function ipv4(src, dst, proto, payload) {
  const h = Buffer.alloc(20);
  h[0] = 0x45; h[1] = 0; h.writeUInt16BE(20 + payload.length, 2);
  h.writeUInt16BE(0x1234, 4); h.writeUInt16BE(0x4000, 6);
  h[8] = 64; h[9] = proto;
  Buffer.from(src.split('.').map(Number)).copy(h, 12);
  Buffer.from(dst.split('.').map(Number)).copy(h, 16);
  h.writeUInt16BE(checksum16(h), 10);
  return Buffer.concat([h, payload]);
}
function udp(sport, dport, payload) {
  const h = Buffer.alloc(8);
  h.writeUInt16BE(sport, 0); h.writeUInt16BE(dport, 2);
  h.writeUInt16BE(8 + payload.length, 4);
  let sum = 0;
  for (let i = 0; i < h.length; i += 2) sum += (h[i] << 8) | h[i + 1];
  let c = (~(sum + payload.length)) & 0xffff;
  h.writeUInt16BE(c, 6);
  return Buffer.concat([h, payload]);
}
function pcap(frames) {
  const gh = Buffer.alloc(24);
  gh.writeUInt32LE(0xa1b2c3d4, 0); gh.writeUInt16LE(2, 4); gh.writeUInt16LE(4, 6);
  gh.writeUInt32LE(0, 8); gh.writeUInt32LE(0, 12); gh.writeUInt32LE(65535, 16);
  gh.writeUInt32LE(1, 20);   // LINKTYPE_ETHERNET
  const out = [gh];
  frames.forEach((f, i) => {
    const rh = Buffer.alloc(16);
    rh.writeUInt32LE(1700000000 + i, 0); rh.writeUInt32LE(0, 4);
    rh.writeUInt32LE(f.length, 8); rh.writeUInt32LE(f.length, 12);
    out.push(rh, f);
  });
  return Buffer.concat(out);
}
function tsharkFields(path, ...fields) {
  const args = ['-r', path, '-T', 'fields', '-E', 'separator=|', '-E', 'occurrence=a', '-2'];
  for (const f of fields) args.push('-e', f);
  return execFileSync('tshark', args, { encoding: 'utf8' })
    .split('\n').filter(Boolean).map(l => l.split('|'));
}
const yes = (v) => v === 'True';

const CHADDR = '02:00:00:00:00:01';
const VICTIM = '192.168.4.50';

// ── 1. an A query is answered with our address, and tshark agrees ───────────
console.log('');
console.log('1. an A query gets an A record pointing at us');
{
  const q = dnsQuery({ type: TYPE_A, rd: true });
  const r = run(q);
  check('the A query is answered, not refused', !r.refused, r.refused ? 'refused' : '');

  const path = join(work, 'a.pcap');
  writeFileSync(path, pcap([
    eth(CHADDR, '02:00:00:00:00:aa', 0x0800, ipv4(VICTIM, OUR_IP, 17, udp(53000, 53, q))),
    eth('02:00:00:00:00:aa', CHADDR, 0x0800, ipv4(OUR_IP, VICTIM, 17, udp(53, 53000, r.buf))),
  ]));
  const rows = tsharkFields(path,
    'dns.id', 'dns.flags.response', 'dns.flags.recdesired', 'dns.flags.recavail',
    'dns.flags.authoritative', 'dns.flags.rcode', 'dns.qry.name', 'dns.qry.type',
    'dns.count.answers', 'dns.a', 'dns.resp.name', 'dns.resp.type');
  check('tshark decodes both frames as DNS', rows.length === 2, String(rows.length));
  const [, ans] = rows;
  check('tshark sees the second frame as a response', yes(ans?.[1]), ans?.[1]);
  check('the transaction id is echoed from the query, not invented',
    ans?.[0] !== undefined && ans?.[0] === rows[0]?.[0] && ans?.[0] !== '',
    `${ans?.[0]} vs query ${rows[0]?.[0]}`);
  check('tshark reads ANCOUNT = 1', ans?.[8] === '1', ans?.[8]);
  check('tshark reads the A record as our address', ans?.[9] === OUR_IP, ans?.[9]);
  check('the answer RR is an A record', ans?.[11] === '1', ans?.[11]);
  check('the answer RR owner is the queried name',
    ans?.[10] === NAME + '.' || ans?.[10] === NAME, ans?.[10]);
  check('RD is echoed, not invented', yes(ans?.[2]), ans?.[2]);
  check('RA is set (we claim to answer)', yes(ans?.[3]), ans?.[3]);
  check('AA is set (authoritative for our own lie)', yes(ans?.[4]), ans?.[4]);
  check('RCODE is NOERROR', ans?.[5] === '0', ans?.[5]);
  check('the question survives the round trip', ans?.[6] === NAME + '.' || ans?.[6] === NAME, ans?.[6]);
}

// ── 2. the honesty rule: AAAA gets no answer record, not a fake A ───────────
console.log('');
console.log('2. an AAAA query is refused a record, not lied to');
{
  const q = dnsQuery({ type: TYPE_AAAA });
  const r = run(q);
  check('the AAAA query is answered (a reply, not silence)', !r.refused);

  const path = join(work, 'aaaa.pcap');
  writeFileSync(path, pcap([
    eth('02:00:00:00:00:aa', CHADDR, 0x0800, ipv4(OUR_IP, VICTIM, 17, udp(53, 53000, r.buf))),
  ]));
  const rows = tsharkFields(path,
    'dns.flags.response', 'dns.flags.rcode', 'dns.count.answers', 'dns.a', 'dns.qry.type', 'dns.resp.type');
  const a = rows[0];
  check('tshark decodes the AAAA reply as a response', yes(a?.[0]), a?.[0]);
  check('the AAAA reply is NOERROR, not NXDOMAIN or SERVFAIL', a?.[1] === '0', a?.[1]);
  check('the AAAA reply carries ZERO answers', a?.[2] === '0', a?.[2]);
  check('the AAAA reply contains NO A record', !a?.[3] || a[3] === '', a?.[3]);
  check('the question type is preserved as AAAA (28)', a?.[4] === '28', a?.[4]);

  // And the trap this is guarding: an A record in an AAAA answer.
  check('so no RR type mismatches its question', !a?.[5] || a[5] === '', a?.[5]);
}

// ── 3. ANY is answered; exotic types are refused a record ───────────────────
console.log('');
console.log('3. ANY is answered, other types are refused a record');
{
  const anyR = run(dnsQuery({ type: TYPE_ANY }));
  check('an ANY query is answered', !anyR.refused);
  if (!anyR.refused) {
    const path = join(work, 'any.pcap');
    writeFileSync(path, pcap([
      eth('02:00:00:00:00:aa', CHADDR, 0x0800, ipv4(OUR_IP, VICTIM, 17, udp(53, 53000, anyR.buf))),
    ]));
    const rows = tsharkFields(path, 'dns.count.answers', 'dns.a');
    check('the ANY reply carries our A record', rows[0]?.[1] === OUR_IP, rows[0]?.[1]);
  }
  const mxR = run(dnsQuery({ type: TYPE_MX }));
  check('an MX query is still answered (NOERROR, no record)', !mxR.refused);
  if (!mxR.refused) {
    const path = join(work, 'mx.pcap');
    writeFileSync(path, pcap([
      eth('02:00:00:00:00:aa', CHADDR, 0x0800, ipv4(OUR_IP, VICTIM, 17, udp(53, 53000, mxR.buf))),
    ]));
    const rows = tsharkFields(path, 'dns.count.answers', 'dns.flags.rcode');
    check('the MX reply is NOERROR with zero answers',
      rows[0]?.[0] === '0' && rows[0]?.[1] === '0', JSON.stringify(rows[0]));
  }
}

// ── 4. RD is ECHOED — a client that did not ask for recursion is not told it got it ──
console.log('');
console.log('4. flags are echoed, not invented');
{
  const r = run(dnsQuery({ type: TYPE_A, rd: false }));
  const path = join(work, 'nord.pcap');
  writeFileSync(path, pcap([
    eth('02:00:00:00:00:aa', CHADDR, 0x0800, ipv4(OUR_IP, VICTIM, 17, udp(53, 53000, r.buf))),
  ]));
  const rows = tsharkFields(path, 'dns.flags.recdesired', 'dns.flags.response');
  check('a query with RD=0 gets RD=0 back', !yes(rows[0]?.[0]), rows[0]?.[0]);
  check('and it is still a response', yes(rows[0]?.[1]), rows[0]?.[1]);
}

// ── 5. the refusals — each of these is a packet we must NOT answer ─────────
console.log('');
console.log('5. what we refuse (each would be a bug if answered)');
{
  // A response, not a query. Answering would be reflecting someone else's traffic.
  const resp = dnsQuery({ type: TYPE_A });
  resp[2] |= 0x80;
  check('a packet with QR already set is refused', run(resp).refused);

  // QDCOUNT=2 — we do not pretend to handle multiple questions, and a partial
  // answer to a two-question query is a silently wrong answer.
  check('QDCOUNT=2 is refused', run(dnsQuery({ type: TYPE_A, qdcount: 2 })).refused);

  // A name that never terminates.
  const trunc = Buffer.concat([dnsQuery({ type: TYPE_A }).subarray(0, 12), Buffer.from([3, 'a'.charCodeAt(0)])]);
  check('a truncated question name is refused', run(trunc).refused);

  // A compression pointer inside the question, which our parser refuses to chase.
  const ptrq = Buffer.concat([dnsQuery({ type: TYPE_A }).subarray(0, 12), Buffer.from([0xc0, 0x0c]), u16(1), u16(1)]);
  check('a compression pointer in the question is refused', run(ptrq).refused);

  // A label longer than 63 octets (RFC 1035 §2.3.4).
  const longlabel = Buffer.concat([dnsQuery({ type: TYPE_A }).subarray(0, 12), Buffer.from([64]), Buffer.alloc(64, 0x61), Buffer.from([0]), u16(1), u16(1)]);
  check('a label over 63 octets is refused', run(longlabel).refused);

  // Class CH — not an internet query.
  check('a non-IN class query is refused', run(dnsQuery({ type: TYPE_A, qclass: 3 })).refused);

  // Nothing at all.
  check('an empty packet is refused', run(Buffer.from([1, 2, 3])).refused);
}

// ── 6. the encoder does not emit trailing junk ─────────────────────────────
console.log('');
console.log('6. the reply is exactly as long as the encoder claims');
{
  const q = dnsQuery({ type: TYPE_A });
  const r = run(q);
  // 12 header + question (NAME + 1 terminator + 4) + 16 for the A RR
  const qlen = 12 + (NAME.length + 1) + 1 + 4;
  check('the A answer is exactly header+question+16 bytes',
    r.buf.length === qlen + 16, `${r.buf.length} vs ${qlen + 16}`);
  const aaaa = run(dnsQuery({ type: TYPE_AAAA }));
  check('the empty AAAA answer is exactly header+question bytes',
    aaaa.buf.length === qlen, `${aaaa.buf.length} vs ${qlen}`);
  check('ARCOUNT is zero on the empty answer (nothing negative-cacheable)',
    aaaa.buf.readUInt16BE(10) === 0, String(aaaa.buf.readUInt16BE(10)));
  check('NSCOUNT is zero on the empty answer',
    aaaa.buf.readUInt16BE(8) === 0, String(aaaa.buf.readUInt16BE(8)));
  check('the A record RDATA is 4 bytes', r.buf.readUInt16BE(r.buf.length - 6) === 4,
    String(r.buf.readUInt16BE(r.buf.length - 6)));
  check('TTL is the 60 we declared', r.buf.readUInt32BE(r.buf.length - 10) === 60,
    String(r.buf.readUInt32BE(r.buf.length - 10)));
}

// ── 7. a different hijack address actually changes the answer ──────────────
console.log('');
console.log('7. the answer follows the address it is given');
{
  const r = run(dnsQuery({ type: TYPE_A }), '10.13.37.1');
  const path = join(work, 'other.pcap');
  writeFileSync(path, pcap([
    eth('02:00:00:00:00:aa', CHADDR, 0x0800, ipv4('10.13.37.1', VICTIM, 17, udp(53, 53000, r.buf))),
  ]));
  const rows = tsharkFields(path, 'dns.a');
  check('tshark reads the address we passed in', rows[0]?.[0] === '10.13.37.1', rows[0]?.[0]);
}

console.log('');
console.log(`PASS — ${pass}/${pass + fail} checks`);
if (fail) {
  console.log(`FAIL — ${fail} failed:`);
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}