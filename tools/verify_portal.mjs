#!/usr/bin/env node
// verify_portal.mjs — pins the captive portal's wire formats and its arming gate.
//
// Same shape as verify_karma.mjs and verify_deauth.mjs, for the same reason:
// the encoder agreeing with itself proves nothing. The DHCP option and the DNS
// answer go into a real libpcap and **tshark** is the judge. A malformed option
// 114 is indistinguishable from a correct one until something that did not
// write it reads it back.
//
// Three things here are deliberately stronger than "it decodes":
//
//   1. The **RFC conformance** checks. Option 114 exists because 160 was
//      deprecated after it broke Polycom handsets (RFC 8910 Appendix B). A
//      hand-rolled encoder that reaches for 160 is silently harmful to a class
//      of devices, so the default is pinned to 114.
//   2. The **honesty** checks. A DNS hijack must not answer a AAAA question
//      with an A record, and the submission parser must not report credentials
//      it does not have. Both are cases where a "working" implementation lies.
//   3. The **gate** checks. The portal cannot use the Karma/Mana allowlist —
//      its victims are strangers by definition — so it has its own arming gate,
//      and what is pinned is that the gate cannot open by accident.
//
// Run: node tools/verify_portal.mjs
// Exit 0 = all green.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const work = mkdtempSync(join(process.env.TMPDIR || tmpdir(), 'portal-'));

// portal.js is browser ESM and imports band.js, so stage both as .mjs — the
// staged copy's import has to be re-pointed at the staged band copy.
writeFileSync(join(work, 'portal.mjs'),
  readFileSync(join(here, '..', 'app', 'www', 'js', 'portal.js'), 'utf8')
    .replace(/from '\.\/band\.js'/g, "from './band.mjs'"));
writeFileSync(join(work, 'band.mjs'), readFileSync(join(here, '..', 'app', 'www', 'js', 'band.js')));
const P = await import(join(work, 'portal.mjs'));

const {
  buildCaptivePortalOption, buildVendorOptions, dhcpOption, ipToBytes,
  CAPTIVE_PORTAL_OPTION, DEPRECATED_CAPTIVE_PORTAL_OPTION, CAPPORT_UNRESTRICTED,
  OPT, DHCP_MAGIC_COOKIE, DHCP_END,
  encodeDnsName, parseDnsQuestion, buildDnsHijackResponse, DNS_TYPE,
  portalPageChunks, joinPortalChunks, parsePortalSubmission,
  portalArm, PORTAL_ARM_TOKEN, PORTAL_DISARMED,
  WIFI_AUTH, twinRejectReason, rankTwinCandidates, selectTwinTarget, nextPortalAction,
} = P;

const URI = 'http://192.168.4.1/portal';
const OUR_IP = '192.168.4.1';
const CHADDR = 'aa:bb:cc:dd:ee:02';

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { pass += 1; } else { fail += 1; failures.push(`${name}${detail ? ` — ${detail}` : ''}`); }
}
const hex = (b) => Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join(' ');
const throws = (fn) => { try { fn(); return false; } catch { return true; } };
const macBytes = (m) => m.split(':').map((x) => parseInt(x, 16));

// ── the packet builders (DHCP is UDP; there is no scapy on this host) ────────

function checksum16(buf) {
  let sum = 0;
  for (let i = 0; i + 1 < buf.length; i += 2) sum += (buf[i] << 8) | buf[i + 1];
  if (buf.length % 2) sum += buf[buf.length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

function eth(dst, src, type, payload) {
  const h = Buffer.alloc(14);
  Buffer.from(macBytes(dst)).copy(h, 0);
  Buffer.from(macBytes(src)).copy(h, 6);
  h.writeUInt16BE(type, 12);
  return Buffer.concat([h, payload]);
}

function ipv4(src, dst, proto, payload) {
  const h = Buffer.alloc(20);
  h[0] = 0x45; h[1] = 0;
  h.writeUInt16BE(20 + payload.length, 2);
  h.writeUInt16BE(0x1234, 4);
  h.writeUInt16BE(0x4000, 6);
  h[8] = 64; h[9] = proto;
  Buffer.from(ipToBytes(src)).copy(h, 12);
  Buffer.from(ipToBytes(dst)).copy(h, 16);
  h.writeUInt16BE(checksum16(h), 10);
  return Buffer.concat([h, payload]);
}

function udp(sport, dport, payload) {
  const h = Buffer.alloc(8);
  h.writeUInt16BE(sport, 0); h.writeUInt16BE(dport, 2);
  h.writeUInt16BE(8 + payload.length, 4);
  h.writeUInt16BE(0, 6); // 0 = "not computed", legal for IPv4 (RFC 768)
  return Buffer.concat([h, payload]);
}

/** RFC 2131 §2 — the 236-byte fixed BOOTP part, then magic cookie + options. */
function bootpReply({ xid, yiaddr, siaddr = OUR_IP, chaddr = CHADDR, vendor }) {
  const b = Buffer.alloc(236);
  b[0] = 2; b[1] = 1; b[2] = 6; b[3] = 0;   // op=BOOTREPLY, htype=ethernet, hlen=6, hops=0
  b.writeUInt32BE(xid, 4);
  b.writeUInt16BE(0, 8);                     // secs
  b.writeUInt16BE(0x8000, 10);               // flags: broadcast
  Buffer.from(ipToBytes('0.0.0.0')).copy(b, 12);        // ciaddr
  Buffer.from(ipToBytes(yiaddr)).copy(b, 16);           // yiaddr
  Buffer.from(ipToBytes(siaddr)).copy(b, 20);           // siaddr
  Buffer.from(ipToBytes('0.0.0.0')).copy(b, 24);        // giaddr
  Buffer.from(macBytes(chaddr)).copy(b, 28);            // chaddr
  return Buffer.concat([b, Buffer.from(vendor)]);
}

// ── the pcap writer (LINKTYPE_ETHERNET here, not 802.11) ────────────────────
function pcap(frames) {
  const head = Buffer.alloc(24);
  head.writeUInt32LE(0xa1b2c3d4, 0); head.writeUInt16LE(2, 4); head.writeUInt16LE(4, 6);
  head.writeUInt32LE(0, 8); head.writeUInt32LE(0, 12); head.writeUInt32LE(65535, 16);
  head.writeUInt32LE(1, 20);                 // LINKTYPE_ETHERNET
  const parts = [head];
  frames.forEach((f, i) => {
    const r = Buffer.alloc(16);
    r.writeUInt32LE(1700000000 + i, 0); r.writeUInt32LE(0, 4);
    r.writeUInt32LE(f.length, 8); r.writeUInt32LE(f.length, 12);
    parts.push(r, Buffer.from(f));
  });
  return Buffer.concat(parts);
}

function tsharkFields(path, ...fields) {
  const args = ['-r', path, '-T', 'fields'];
  for (const f of fields) args.push('-e', f);
  return execFileSync('tshark', args, { encoding: 'utf8' })
    .trim().split('\n').filter(Boolean).map((r) => r.split('\t'));
}

let haveTshark = true;
try { execFileSync('tshark', ['--version'], { stdio: 'ignore' }); } catch { haveTshark = false; }
check('tshark is available for the cross-check', haveTshark);

// ── 1. the DHCP option, judged by tshark ───────────────────────────────────
if (haveTshark) {
  const vendor = buildVendorOptions({
    serverId: OUR_IP, router: OUR_IP, dns: OUR_IP,
    leaseTime: 3600, captivePortalUri: URI, allowIpLiteral: true,
  });

  check('the vendor blob opens with the magic cookie (RFC 2131 §2)',
    (vendor[0] === 0x63 && vendor[1] === 0x82 && vendor[2] === 0x53 && vendor[3] === 0x63), hex(vendor.subarray(0, 4)));
  check('and closes with the END option 255', vendor[vendor.length - 1] === DHCP_END);

  const packet = eth('ff:ff:ff:ff:ff:ff', '02:00:00:00:00:01', 0x0800,
    ipv4(OUR_IP, '255.255.255.255', 17,
      udp(67, 68, bootpReply({ xid: 0xdeadbeef, yiaddr: '192.168.4.50', vendor }))));

  const path = join(work, 'portal.pcap');
  writeFileSync(path, pcap([packet]));
  const rows = tsharkFields(path, 'dhcp.option.captive_portal', 'dhcp.option.dhcp_server_id',
    'dhcp.option.router', 'dhcp.option.domain_name_server', 'dhcp.ip.your');

  check('tshark decodes the packet as DHCP at all', rows.length === 1, String(rows.length));
  const [capport, serverId, router, dns, yiaddr] = rows[0] || [];
  check('tshark reads the Captive-Portal option as the URI we encoded',
    capport === URI, `${JSON.stringify(capport)} vs ${JSON.stringify(URI)}`);
  check('tshark reads our server identifier', serverId === OUR_IP, serverId);
  check('tshark reads the router as us (so the client sends its traffic here)', router === OUR_IP, router);
  check('tshark reads the DNS server as us (so every lookup comes here)', dns === OUR_IP, dns);
  check('tshark reads the offered address', yiaddr === '192.168.4.50', yiaddr);

  // The option's own shape, independent of tshark: code | len | uri, no NUL.
  const opt = buildCaptivePortalOption(URI, { allowIpLiteral: true });
  check('option 114 is the code point (not the deprecated 160)', opt[0] === 114, String(opt[0]));
  check('the length octet counts the URI octets only', opt[1] === URI.length, `${opt[1]} vs ${URI.length}`);
  check('the URI is NOT null-terminated (RFC 8910 §2.1)', opt[opt.length - 1] !== 0, hex(opt.subarray(-1)));
  check('the URI round-trips exactly', Buffer.from(opt.subarray(2)).toString('utf8') === URI);

  check('RFC 8910 Appendix B: 160 is reachable only when asked for by name',
    buildCaptivePortalOption(URI, { option: DEPRECATED_CAPTIVE_PORTAL_OPTION, allowIpLiteral: true })[0] === 160);
  check('and the default stays 114', buildCaptivePortalOption(URI, { allowIpLiteral: true })[0] === 114);
  check('the unrestricted URN is carryable verbatim',
    Buffer.from(buildCaptivePortalOption(CAPPORT_UNRESTRICTED).subarray(2)).toString('utf8') === CAPPORT_UNRESTRICTED);
}

// ── 2. the option's guard rails ────────────────────────────────────────────
check('a URI over 255 octets is REFUSED, not truncated',
  throws(() => buildCaptivePortalOption(`http://x/${'a'.repeat(300)}`, { allowIpLiteral: true })));
check('a bare IP-literal URI is refused unless the caller opts in (RFC 8910 §2)',
  throws(() => buildCaptivePortalOption('http://192.168.4.1/')));
check('a NUL in the URI is refused', throws(() => buildCaptivePortalOption('http://x/\0y', { allowIpLiteral: true })));
check('an empty URI is refused', throws(() => buildCaptivePortalOption('')));
check('an option value over 255 octets is refused at the option layer',
  throws(() => dhcpOption(1, new Uint8Array(256))));
check('option 54 (server id) is mandatory',
  throws(() => buildVendorOptions({ router: OUR_IP, captivePortalUri: URI, allowIpLiteral: true })));

// ── 3. the DNS hijack, judged by tshark ────────────────────────────────────
if (haveTshark) {
  const q = (name, qtype, id) => {
    const n = encodeDnsName(name);
    const m = Buffer.alloc(12 + n.length + 4);
    m.writeUInt16BE(id, 0);
    m.writeUInt16BE(0x0100, 2);              // RD set
    m.writeUInt16BE(1, 4);                   // QDCOUNT
    m.set(n, 12);
    m.writeUInt16BE(qtype, 12 + n.length);
    m.writeUInt16BE(1, 12 + n.length + 2);   // QCLASS IN
    return m;
  };

  const qA = q('connectivitycheck.gstatic.com', DNS_TYPE.A, 0x4242);
  const qAAAA = q('ipv6.example.test', DNS_TYPE.AAAA, 0x4243);
  const rA = buildDnsHijackResponse(qA, OUR_IP).message;
  const rAAAA = buildDnsHijackResponse(qAAAA, OUR_IP).message;

  const path = join(work, 'dns.pcap');
  writeFileSync(path, pcap([
    eth('02:00:00:00:00:01', CHADDR, 0x0800, ipv4('192.168.4.50', OUR_IP, 17, udp(53000, 53, qA))),
    eth(CHADDR, OUR_IP === '' ? '' : '02:00:00:00:00:01', 0x0800, ipv4(OUR_IP, '192.168.4.50', 17, udp(53, 53000, rA))),
    eth('02:00:00:00:00:01', CHADDR, 0x0800, ipv4(OUR_IP, '192.168.4.50', 17, udp(53, 53000, rAAAA))),
  ]));

  const rows = tsharkFields(path, 'dns.id', 'dns.flags.response', 'dns.flags.recdesired',
    'dns.flags.recavail', 'dns.qry.name', 'dns.a', 'dns.count.answers', 'dns.flags.rcode');

  check('tshark decodes 3 DNS frames', rows.length === 3, String(rows.length));
  // FT_BOOLEAN fields come back as the strings 'True'/'False', NOT '1'/'0' —
  // the same trap references/transmit-and-attacks.md records for
  // wlan.fixed.capabilities.*. Comparing to '1' silently fails against a
  // perfectly good packet.
  const [qr1, qr2, qr3] = rows;
  const yes = (v) => v === 'True';
  check('the query carries the name we asked for', qr1?.[4] === 'connectivitycheck.gstatic.com', qr1?.[4]);
  check('tshark sees the query as a query', !yes(qr1?.[1]), qr1?.[1]);
  check('the answer echoes the transaction id', qr2?.[0] === '0x4242', qr2?.[0]);
  check('tshark sees the response as a response', yes(qr2?.[1]), qr2?.[1]);
  check('RD is ECHOED from the query (RFC 1035 §4.1.1)', yes(qr2?.[2]), qr2?.[2]);
  check('RA is set, so the client does not retry elsewhere', yes(qr2?.[3]), qr2?.[3]);
  check('the answer name is the SAME name the client asked for', qr2?.[4] === 'connectivitycheck.gstatic.com', qr2?.[4]);
  check('tshark reads the A record as our address', qr2?.[5] === OUR_IP, qr2?.[5]);
  check('exactly one answer record', qr2?.[6] === '1', qr2?.[6]);
  check('RCODE is NOERROR', qr2?.[7] === '0', qr2?.[7]);

  // tshark prints an ABSENT field as an empty string, not as undefined.
  check('an AAAA query gets NOERROR with ZERO answers — not a stuffed A record',
    (qr3?.[5] ?? '') === '' && qr3?.[6] === '0', `a=${JSON.stringify(qr3?.[5])} answers=${qr3?.[6]}`);
  check('and it still echoes the id and sets QR', qr3?.[0] === '0x4243' && yes(qr3?.[1]), `${qr3?.[0]} ${qr3?.[1]}`);
}

// ── 4. DNS parsing guards ──────────────────────────────────────────────────
check('a query with no question is refused', throws(() => parseDnsQuestion(new Uint8Array(12))));
check('a truncated message is refused', throws(() => parseDnsQuestion(Uint8Array.from([0x12, 0x34, 0x01, 0x00]))));
{
  const q = Buffer.alloc(12 + 17);
  q.writeUInt16BE(1, 4);
  q.set(encodeDnsName('a.bc'), 12);
  const p = parseDnsQuestion(q);
  check('parseDnsQuestion recovers a multi-label name', p.qname === 'a.bc', p.qname);
  check('parseDnsQuestion keeps the question bytes for echoing', p.questionBytes.length === 10, String(p.questionBytes.length));
}
check('a label over 63 octets is refused', throws(() => encodeDnsName(`${'a'.repeat(64)}.com`)));
check('an empty label is refused', throws(() => encodeDnsName('a..b')));

// ── 5. the page chunking must be lossless, including UTF-8 ────────────────
{
  const page = `<!doctype html><meta charset="utf-8"><h1>Café 駅 🜂 — ${'x'.repeat(2000)}</h1>`;
  const chunks = portalPageChunks(page, 512);
  check('the page splits into more than one chunk', chunks.length > 1, String(chunks.length));
  check('every chunk is within the size limit', chunks.every((c) => c.length <= 512),
    chunks.map((c) => c.length).join(','));
  check('no chunk begins with a UTF-8 continuation byte (a split sequence)',
    chunks.every((c) => (c[0] & 0xc0) !== 0x80));
  const rejoined = new TextDecoder().decode(joinPortalChunks(chunks));
  check('the reassembled page is byte-identical to the original', rejoined === page);
  // The bug this is really guarding: slicing the *string* splits the surrogate pair.
  const naive = Array.from({ length: Math.ceil(page.length / 512) }, (_, i) => page.slice(i * 512, (i + 1) * 512)).join('');
  check('(control) a naive string slice survives here only by luck of alignment', naive === page);
  const emoji = '🜂'.repeat(4);
  check('a chunk boundary never lands mid-emoji', portalPageChunks(emoji, 3).every((c) => new TextDecoder('utf-8', { fatal: true }).decode(c) !== ''));
  check('chunk size is clamped to a sane floor', portalPageChunks('abc', 1)[0].length >= 1);
  check('an empty page yields no chunks', portalPageChunks('').length === 0);
}

// ── 6. the submission parser must not over-claim ──────────────────────────
{
  const good = parsePortalSubmission('username=brad%40example.com&password=hunter2&submit=Sign+in');
  check('a real submission parses', good.ok === true, good.reason);
  check('the username is decoded (percent- and plus-encoded)', good.username === 'brad@example.com', good.username);
  check('the password is decoded', good.password === 'hunter2', good.password);
  check('unrelated fields are kept, not dropped', good.fields.submit === 'Sign in', good.fields.submit);

  const blank = parsePortalSubmission('username=bob&password=&submit=Go');
  check('a BLANK password is not reported as captured', blank.ok === false, blank.reason);
  check('...and says why', /blank/.test(blank.reason), blank.reason);

  const noPw = parsePortalSubmission('email=bob%40x.com&submit=Go');
  check('a body with no password field is not reported as captured', noPw.ok === false, noPw.reason);
  check('...and it is warned about, not silent', noPw.warnings.length > 0, JSON.stringify(noPw.warnings));

  check('an empty body is not reported as captured', parsePortalSubmission('').ok === false);
  check('a blank body is not reported as captured', parsePortalSubmission('   \n ').ok === false);
  check('a body with no fields is not reported as captured', parsePortalSubmission('&&&').ok === false);

  const alt = parsePortalSubmission('user=admin&passwd=s3cret');
  check('alternate field names are recognised', alt.ok === true && alt.password === 's3cret', alt.reason);

  const dup = parsePortalSubmission('password=a&password=b');
  check('a duplicated password field keeps both rather than silently losing one',
    dup.password.includes('a') && dup.password.includes('b'), dup.password);
}

// ── 7. the arming gate must not open by accident ──────────────────────────
{
  const base = { ssid: 'Cafe-Guest', channel: 6, captivePortalUri: URI };

  check('the default state is disarmed', portalArm({}).armed === false);
  check('...and reports the disarmed mode', portalArm({}).mode === PORTAL_DISARMED);

  const armed = portalArm({ ...base, acknowledge: PORTAL_ARM_TOKEN });
  check('the exact token arms it', armed.armed === true, JSON.stringify(armed.problems));
  check('an armed portal is attributed as portal/armed, not as a scoped hit', armed.attribution === 'portal/armed');
  check('arming states the warning out loud', /stranger/i.test(armed.warning || ''), armed.warning);

  // Every near-miss must fall through to disarmed, exactly as SCOPE_LAB_ANY does.
  for (const bad of ['true', 'TRUE', '1', 1, 'yes', 'on', 'ARM', 'arm', 'i-own-this-frequency',
    'I-OWN-THIS-FREQUENCY', 'I-own-this-frequency ', ' I-own-this-frequency', 'I-own-this-frequency!!',
    '', null, undefined, true, [], {}]) {
    const r = portalArm({ ...base, acknowledge: bad });
    check(`near-miss acknowledgement ${JSON.stringify(bad)} does NOT arm`, r.armed === false);
  }

  check('an empty SSID is refused even with the right token',
    portalArm({ ...base, ssid: '', acknowledge: PORTAL_ARM_TOKEN }).armed === false);
  check('a whitespace SSID is refused',
    portalArm({ ...base, ssid: '   ', acknowledge: PORTAL_ARM_TOKEN }).armed === false);
  check('an SSID over 32 octets is refused',
    portalArm({ ...base, ssid: 'a'.repeat(33), acknowledge: PORTAL_ARM_TOKEN }).armed === false);
  check('a 32-octet SSID is allowed',
    portalArm({ ...base, ssid: 'a'.repeat(32), acknowledge: PORTAL_ARM_TOKEN }).armed === true);
  check('channel 0 is refused', portalArm({ ...base, channel: 0, acknowledge: PORTAL_ARM_TOKEN }).armed === false);
  check('channel 15 is refused (the S3 is 2.4 GHz only)',
    portalArm({ ...base, channel: 15, acknowledge: PORTAL_ARM_TOKEN }).armed === false);
  check('a non-integer channel is refused',
    portalArm({ ...base, channel: 6.5, acknowledge: PORTAL_ARM_TOKEN }).armed === false);
  check('a group-address BSSID is refused',
    portalArm({ ...base, bssid: '01:00:5e:00:00:01', acknowledge: PORTAL_ARM_TOKEN }).armed === false);
  check('a malformed BSSID is refused',
    portalArm({ ...base, bssid: 'not-a-mac', acknowledge: PORTAL_ARM_TOKEN }).armed === false);
  check('a blank captivePortalUri is refused rather than defaulted',
    portalArm({ ...base, captivePortalUri: '  ', acknowledge: PORTAL_ARM_TOKEN }).armed === false);
  check('problems are all reported, not just the first',
    portalArm({ ssid: '', channel: 99, acknowledge: 'nope' }).problems.length === 3,
    JSON.stringify(portalArm({ ssid: '', channel: 99, acknowledge: 'nope' }).problems));
}

// ── 8. seeding the twin from the air ──────────────────────────────────────
{
  const scan = [
    { ssid: 'Cafe-Guest', bssid: 'aa:bb:cc:00:00:01', rssi: -41, ch: 6, auth: 3 },  // wpa2_psk
    { ssid: 'Cafe-Guest', bssid: 'aa:bb:cc:00:00:02', rssi: -70, ch: 6, auth: 3 },  // same SSID, second radio
    { ssid: 'FrontDesk', bssid: 'aa:bb:cc:00:00:03', rssi: -55, ch: 11, auth: 4 },  // wpa/wpa2
    { ssid: 'OpenLobby', bssid: 'aa:bb:cc:00:00:04', rssi: -30, ch: 1, auth: 0 },   // open
    { ssid: 'OldRouter', bssid: 'aa:bb:cc:00:00:05', rssi: -80, ch: 1, auth: 1 },   // wep
    { ssid: 'ModernHome', bssid: 'aa:bb:cc:00:00:06', rssi: -44, ch: 6, auth: 6 },  // wpa3 only
    { ssid: 'OfficeWiFi', bssid: 'aa:bb:cc:00:00:07', rssi: -60, ch: 11, auth: 5 }, // enterprise
    { ssid: '', bssid: 'aa:bb:cc:00:00:08', rssi: -50, ch: 6, auth: 3 },            // hidden
    { ssid: 'FiveGig', bssid: 'aa:bb:cc:00:00:09', rssi: -38, ch: 36, auth: 3 },    // 5 GHz
    { ssid: 'NoRssi', bssid: 'aa:bb:cc:00:00:0a', rssi: null, ch: 1, auth: 3 },     // unknown signal
  ];
  const byName = (list, n) => list.find((c) => c.ssid === n);

  const ranked = rankTwinCandidates(scan);
  check('ranking returns every AP', ranked.length === scan.length, String(ranked.length));
  check('ranking sorts strongest first', ranked[0].rssi === -30, JSON.stringify(ranked[0]));
  check('an UNKNOWN rssi sorts last, not as 0 dBm', ranked[ranked.length - 1].ssid === 'NoRssi', ranked[ranked.length - 1].ssid);
  check('the open AP is flagged not cloneable', byName(ranked, 'OpenLobby').cloneable === false);
  check('...and says why in plain words', /nothing to crack/.test(byName(ranked, 'OpenLobby').why));
  check('WPA3-only is refused, naming SAE', /SAE/.test(byName(ranked, 'ModernHome').why), byName(ranked, 'ModernHome').why);
  check('enterprise is refused as 802.1X', /802\.1X/.test(byName(ranked, 'OfficeWiFi').why));
  check('the 5 GHz AP is refused on the S3 radio', /2\.4 GHz/.test(byName(ranked, 'FiveGig').why));
  check('the hidden AP is refused', /hidden/.test(byName(ranked, '').why));
  check('WEP is refused as the wrong tool', /wrong tool/.test(byName(ranked, 'OldRouter').why));
  check('onlyCloneable keeps just the WPA-PSK set',
    rankTwinCandidates(scan, { onlyCloneable: true }).every((c) => c.cloneable));

  check('selection REFUSES with no target named — it ranks, it does not choose',
    selectTwinTarget(scan, {}).ok === false);
  const sel = selectTwinTarget(scan, { ssid: 'FrontDesk' });
  check('a named cloneable AP is selected', sel.ok === true, sel.reason);
  check('the twin takes the target SSID', sel.twin.ssid === 'FrontDesk');
  check('the twin takes the target BSSID', sel.twin.bssid === 'aa:bb:cc:00:00:03');
  check("the twin's channel is FORCED to the target's (one radio)", sel.twin.channel === 11, String(sel.twin.channel));
  check('the selection says out loud that a scan shows no clients', /never its clients/.test(sel.note));

  check('an AP not in the scan is REFUSED, never substituted for',
    selectTwinTarget(scan, { ssid: 'NotHere' }).ok === false);
  check('...and the refusal names what was asked for',
    /NotHere/.test(selectTwinTarget(scan, { ssid: 'NotHere' }).reason));
  check('a refused AP yields NO twin at all', selectTwinTarget(scan, { ssid: 'OpenLobby' }).twin === undefined);
  check('picking an open AP is refused', selectTwinTarget(scan, { ssid: 'OpenLobby' }).ok === false);
  check('picking a WPA3-only AP is refused', selectTwinTarget(scan, { ssid: 'ModernHome' }).ok === false);
  check('picking the 5 GHz AP is refused', selectTwinTarget(scan, { ssid: 'FiveGig' }).ok === false);

  const ambiguous = selectTwinTarget(scan, { ssid: 'Cafe-Guest' });
  check('one SSID on two BSSIDs is REFUSED rather than picked for you', ambiguous.ok === false);
  check('...and it offers the candidates instead', Array.isArray(ambiguous.candidates) && ambiguous.candidates.length === 2);
  check('naming the BSSID resolves the ambiguity',
    selectTwinTarget(scan, { ssid: 'Cafe-Guest', bssid: 'aa:bb:cc:00:00:02' }).ok === true);

  check('a malformed BSSID is refused', /not a MAC/.test(twinRejectReason({ ssid: 'x', bssid: 'nope', ch: 1, auth: 3 })));
  check('a group-address BSSID is refused', /group address/.test(twinRejectReason({ ssid: 'x', bssid: '01:00:5e:00:00:01', ch: 1, auth: 3 })));
  check('channel 0 is refused', /2\.4 GHz/.test(twinRejectReason({ ssid: 'x', bssid: 'aa:bb:cc:00:00:01', ch: 0, auth: 3 })));
}

// ── 9. portal-up-then-deauth, enforced rather than hoped for ──────────────
{
  const targets = ['aa:bb:cc:00:00:01'];

  check('with nothing up, the first move is to bring the twin up',
    nextPortalAction({}).action === 'bring_up_twin');
  const wait = nextPortalAction({ twinUp: true, twinBeaconConfirmed: false, deauthTargets: targets });
  check('twin up but NOT confirmed -> wait, even holding targets', wait.action === 'wait_for_beacon', wait.action);
  check('...and the reason names the race it is avoiding', /finds the real one/.test(wait.reason), wait.reason);
  check('confirmed + targets -> deauth',
    nextPortalAction({ twinUp: true, twinBeaconConfirmed: true, deauthTargets: targets }).action === 'deauth');
  check('confirmed but nothing to knock off -> scan for clients',
    nextPortalAction({ twinUp: true, twinBeaconConfirmed: true, deauthTargets: [] }).action === 'scan_for_clients');

  // THE property, exhaustively over the other flags: no combination can produce
  // a deauth while the twin is unconfirmed. A single hand-picked case would miss
  // the combination that leaks.
  let leaked = null;
  for (const twinUp of [false, true]) {
    for (const tg of [[], targets]) {
      for (const rounds of [0, 1, 5, 9]) {
        for (const landed of [0, 1, 3]) {
          for (const creds of [0, 2]) {
            const st = {
              twinUp, twinBeaconConfirmed: false, deauthTargets: tg,
              deauthRounds: rounds, clientsLanded: landed, credentialsCaptured: creds,
            };
            if (nextPortalAction(st).action === 'deauth') leaked = st;
          }
        }
      }
    }
  }
  check('EXHAUSTIVE: no unconfirmed-twin state can emit a deauth', leaked === null, JSON.stringify(leaked));

  const spent = nextPortalAction({ twinUp: true, twinBeaconConfirmed: true, deauthTargets: targets, deauthRounds: 5 });
  check('giving up after the round cap is NOT an allowed action', spent.allowed === false, spent.action);
  check('...and it says stop rather than hammer', /stop rather than hammer/.test(spent.reason), spent.reason);
  check('a landed client means serve the page',
    nextPortalAction({ twinUp: true, twinBeaconConfirmed: true, deauthTargets: targets, deauthRounds: 1, clientsLanded: 1 }).action === 'serve_portal');
  check('every action carries a reason', [
    {}, { twinUp: true }, { twinUp: true, twinBeaconConfirmed: true },
    { twinUp: true, twinBeaconConfirmed: true, deauthTargets: targets },
    { twinUp: true, twinBeaconConfirmed: true, deauthTargets: targets, deauthRounds: 9 },
    { twinUp: true, twinBeaconConfirmed: true, deauthTargets: targets, clientsLanded: 1 },
  ].every((s) => typeof nextPortalAction(s).reason === 'string' && nextPortalAction(s).reason.length > 0));
}

// ── report ─────────────────────────────────────────────────────────────────
rmSync(work, { recursive: true, force: true });
console.log(`\nverify_portal: ${pass} passed, ${fail} failed`);
if (fail) {
  console.log('\nFAILURES:');
  for (const f of failures) console.log('  ✗ ' + f);
  process.exit(1);
}
console.log('all green — option 114, the DNS hijack and the gate agree with tshark and the RFCs\n');
