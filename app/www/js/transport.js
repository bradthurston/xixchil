// transport.js — USB-OTG serial transport over @leeskies/capacitor-usb-serial.
//
// The plugin is handle-based and moves binary as base64:
//   listDevices() -> [{ deviceId, deviceName, driverType, hasPermission, ... }]
//   requestPermission({ deviceId }) -> { granted }
//   open({ deviceId, portNum }) -> { portId }
//   setParameters({ portId, baudRate, dataBits, stopBits, parity })
//   addListener('data', ({ data }) => ...)   // base64
//   startReading({ portId })
//   write({ portId, data })                  // base64
//
// No root required. This is the whole reason the phone-first design works.

const BAUD = 115200;

function plugin() {
  const p = window.Capacitor?.Plugins?.UsbSerial;
  if (!p) throw new Error('UsbSerial plugin not available (not running in the app?)');
  return p;
}

export function bytesToBase64(u8) {
  let s = '';
  const CH = 0x8000;
  for (let i = 0; i < u8.length; i += CH) {
    s += String.fromCharCode.apply(null, u8.subarray(i, i + CH));
  }
  return btoa(s);
}

export function base64ToBytes(b64) {
  const s = atob(b64);
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}

export class UsbTransport {
  constructor({ onData, onStatus } = {}) {
    this.portId = null;
    this.deviceId = null;
    this.subs = [];
    this.onData = onData || (() => {});
    this.onStatus = onStatus || (() => {});
  }

  get connected() {
    return this.portId !== null;
  }

  async listDevices() {
    const { devices } = await plugin().listDevices();
    return devices || [];
  }

  async connect(device) {
    if (this.connected) await this.disconnect();

    if (!device.hasPermission) {
      const { granted } = await plugin().requestPermission({ deviceId: device.deviceId });
      if (!granted) throw new Error('USB permission denied');
    }

    const { portId } = await plugin().open({ deviceId: device.deviceId, portNum: 0 });
    this.portId = portId;
    this.deviceId = device.deviceId;

    await plugin().setParameters({
      portId,
      baudRate: BAUD,
      dataBits: 8,
      stopBits: 1,
      parity: 'none',
    });

    this.subs.push(await plugin().addListener('data', ({ data }) => {
      this.onData(base64ToBytes(data));
    }));
    this.subs.push(await plugin().addListener('error', (e) => {
      this.onStatus('error', e);
    }));
    this.subs.push(await plugin().addListener('detached', (e) => {
      this.onStatus('detached', e);
      this.portId = null;
      this.deviceId = null;
    }));

    await plugin().startReading({ portId });
    this.onStatus('connected', { portId, deviceId: device.deviceId, driver: device.driverType });
    return { portId };
  }

  async send(bytes) {
    if (!this.connected) throw new Error('not connected');
    await plugin().write({ portId: this.portId, data: bytesToBase64(bytes) });
  }

  async disconnect() {
    for (const s of this.subs) {
      try { await s.remove(); } catch { /* already gone */ }
    }
    this.subs = [];
    if (this.portId !== null) {
      try { await plugin().stopReading({ portId: this.portId }); } catch { /* ignore */ }
      try { await plugin().close({ portId: this.portId }); } catch { /* ignore */ }
    }
    this.portId = null;
    this.deviceId = null;
    this.onStatus('disconnected', {});
  }
}
