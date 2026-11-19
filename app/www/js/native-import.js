// native-import.js — the phone's own door for a capture shared from another app.
//
// "Share → Radio Console" hands the app a content:// URI, not a File. The native side
// copies the bytes and this asks for them once; the bytes then go into the same
// importer the file picker feeds, so a shared capture and a picked one take exactly
// one code path — there is no second import implementation to drift.
//
// The plugin is reached through window.Capacitor rather than imported, the way
// transport.js and gps.js reach theirs. In a browser there is no plugin, and every
// function here reports "nothing shared" instead of throwing, so the web build keeps
// working.

const plugin = () => window.Capacitor?.Plugins?.CaptureImport || null;

/** Is there a native share door on this device at all? */
export function hasNativeImport() {
  return !!plugin();
}

/** base64 → Uint8Array. */
export function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Take whatever another app shared, if anything, and hand it to `receive` as
 * { name, bytes }. Returns true when something was handed over.
 *
 * The native side clears its stash on read, so a share is imported once — not again
 * on every resume.
 */
export async function takeSharedCapture(receive) {
  const p = plugin();
  if (!p) return false;

  let res;
  try {
    res = await p.getPending();
  } catch (e) {
    console.warn('[import] getPending failed:', e);
    return false;
  }

  if (!res?.pending) return false;
  if (res.error) throw new Error(res.error);

  receive({ name: res.name || 'shared-capture', bytes: b64ToBytes(res.base64 || '') });
  return true;
}
