// icons.js — inline SVG icon set. No emoji, ever: Brad has flagged emoji-as-icons
// as looking cheap across multiple projects. One stroke width, one viewBox, so the
// whole set reads as a single design system.
//
// This is the functional set for the spike. The full visual design is a separate
// pass (see the capacitor-android-development skill: visual work is Sonnet's).

const PATHS = {
  plug:     '<path d="M9 2v6"/><path d="M15 2v6"/><path d="M6 8h12v3a6 6 0 0 1-6 6 6 6 0 0 1-6-6V8Z"/><path d="M12 17v5"/>',
  antenna:  '<path d="M12 13v8"/><path d="M5.5 9.5a9 9 0 0 1 13 0"/><path d="M8.5 12.5a5 5 0 0 1 7 0"/><circle cx="12" cy="12" r="1.2"/>',
  scan:     '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  capture:  '<path d="M3 12h4l2-5 3 10 2-5h5"/>',
  analyze:  '<path d="M4 19V5"/><path d="M4 19h16"/><rect x="7" y="12" width="2.6" height="5"/><rect x="11.5" y="9" width="2.6" height="8"/><rect x="16" y="6" width="2.6" height="11"/>',
  analysis: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5"/><path d="M9 13h7"/><path d="M9 17h5"/>',
  attack:   '<path d="M13 2 4.5 13.5H11l-1 8.5 8.5-11.5H12z"/>',
  key:      '<circle cx="8" cy="14" r="4"/><path d="m11 11 8-8"/><path d="m17 3 3 3"/><path d="m14.5 5.5 3 3"/>',
  refresh:  '<path d="M20 11a8 8 0 1 0-2.3 6"/><path d="M20 5v6h-6"/>',
  link:     '<path d="M9.5 14.5 14.5 9.5"/><path d="M11 7l1.5-1.5a3.5 3.5 0 0 1 5 5L16 12"/><path d="M13 17l-1.5 1.5a3.5 3.5 0 0 1-5-5L8 12"/>',
  unlink:   '<path d="M9.5 14.5 14.5 9.5"/><path d="M11 7l1.5-1.5a3.5 3.5 0 0 1 5 5L16 12"/><path d="M13 17l-1.5 1.5a3.5 3.5 0 0 1-5-5L8 12"/><path d="m3 3 18 18"/>',
  alert:    '<path d="M12 3 2.5 20h19z"/><path d="M12 10v4"/><path d="M12 17.2v.1"/>',
  check:    '<path d="m4 12.5 5 5L20 6.5"/>',
  chevron:  '<path d="m9 6 6 6-6 6"/>',
};

export function Icon(name, { size = 22, strokeWidth = 1.75, className = '' } = {}) {
  const path = PATHS[name] || PATHS.alert;
  return `<svg class="icon ${className}" width="${size}" height="${size}" viewBox="0 0 24 24" ` +
    `fill="none" stroke="currentColor" stroke-width="${strokeWidth}" ` +
    `stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${path}</svg>`;
}

export const STAGE_ICONS = {
  capture: 'capture',
  analyze: 'analyze',
  analysis: 'analysis',
  attack: 'attack',
};
