// band.js — the band plan, in one place.
//
// This mirrors `wifi_channel_ok()` in the firmware's `src/protocol.h`. The
// firmware is the authority: the radio is the side that cannot be wrong, and it
// refuses a channel it cannot tune (`tx.h` says why the clamps live there and
// not in the app). The app keeps its own copy for the same reason it keeps its
// own frame builder — it has to answer "is this a channel?" before a device is
// attached, and the builder has to stay a pure function with no transport.
//
// 5 GHz membership is a WHITELIST of real channel centres, not a range: 16, 35
// and 99 are not channels, and `36..177` would accept all three.
//
// The app validates against the union of both bands. Whether the attached board
// can actually tune a 5 GHz channel is the firmware's call — and the firmware
// already states its own capability as `status.bands` ("2.4" or "2.4+5").

/** 2.4 GHz channel numbers, 1..14. */
export const CHANNELS_24 = Object.freeze([
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
]);

/** 5 GHz channel centres, 36..177. Which are usable varies by regulatory domain. */
export const CHANNELS_5 = Object.freeze([
  36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
  132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177,
]);

const ANY = new Set([...CHANNELS_24, ...CHANNELS_5]);

/** Any channel either band defines. Capability is the firmware's call, not ours. */
export function channelOk(ch) {
  return Number.isInteger(ch) && ANY.has(ch);
}

/** 2.4 GHz only — for elements that exist in that band alone (§9.4.2.4). */
export function channel24Ok(ch) {
  return Number.isInteger(ch) && ch >= 1 && ch <= 14;
}

/** Human-readable statement of the plan, for error messages. */
export function channelHint() {
  return 'channel must be 1..14 (2.4 GHz) or a 5 GHz centre (36, 40, 44 ... 177)';
}

/** Parse `status.bands` into a list. Anything unrecognised is treated as 2.4-only. */
export function bandsOf(status) {
  return String(status?.bands ?? '').includes('5') ? ['2.4', '5'] : ['2.4'];
}
