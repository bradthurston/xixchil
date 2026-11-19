// Local bridge defaults — copy this file to `bridge-defaults.js` and edit it.
//
// WHY THIS ISN'T IN THE REPO
// --------------------------
// A bridge URL and its token are *yours*, not the project's: the URL is your
// network and the token is a live credential for your GPU box. Neither belongs
// in a public tree, and neither belongs in git history where deleting them
// later does not actually remove them.
//
// So the tracked default is empty. `bridge-defaults.js` is gitignored. If it is
// absent — which is what a fresh clone looks like — the app simply starts with
// no bridge configured and asks you for a URL and token in Settings.
//
//   cp app/www/js/bridge-defaults.example.js app/www/js/bridge-defaults.js
//
// Then fill in the two values. The token is the contents of the `token` file on
// whatever host runs the bridge (see bridge/README.md).
window.BRIDGE_DEFAULTS = {
  url:   '',   // e.g. 'http://192.168.1.50:8099'  or  'http://mybox.example:8099'
  token: '',   // the bridge host's ./token
};
