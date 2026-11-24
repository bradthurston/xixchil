package io.github.bradthurston.xixchil;

import android.content.Intent;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

/**
 * Open another app on this phone — currently one: Tailscale, the tunnel the crack
 * bridge is reached over when it is not on the local network.
 *
 * Why a plugin and not a web link: their app exposes no public "connect" action, so
 * the only honest thing a side app can do is open it and let the tunnel state come
 * from the bridge test. A web-side `location.href = "tailscale://"` is not possible
 * either — there is no such scheme registered, and a WebView is not allowed to start
 * a foreign activity without a user gesture Android trusts.
 *
 * Why <queries> in the manifest: from Android 11, package visibility is filtered, so
 * getLaunchIntentForPackage returns null for a package the app has not declared —
 * the call silently fails and the button looks dead. The manifest names
 * com.tailscale.ipn for exactly this reason, and `canOpen` exists so the UI can tell
 * "installed but we opened it" from "not installed at all".
 */
@CapacitorPlugin(name = "AppLauncher")
public class AppLauncherPlugin extends Plugin {

    /** Does this package resolve to something launchable? False when it is absent —
     *  which is a fact about the phone, not an error. */
    @PluginMethod
    public void canOpen(PluginCall call) {
        JSObject out = new JSObject();
        out.put("installed", launchIntentFor(call.getString("package")) != null);
        call.resolve(out);
    }

    /** Start it. FLAG_ACTIVITY_NEW_TASK because the WebView is not an activity
     *  context; without it the call throws. */
    @PluginMethod
    public void open(PluginCall call) {
        String pkg = call.getString("package");
        Intent intent = launchIntentFor(pkg);
        if (intent == null) {
            // Say which way it failed: an app that is not installed and an app the
            // manifest has not declared both look like "nothing happened".
            call.reject("not launchable (not installed, or not declared in <queries>): " + pkg);
            return;
        }
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        getContext().startActivity(intent);
        JSObject out = new JSObject();
        out.put("opened", pkg);
        call.resolve(out);
    }

    private Intent launchIntentFor(String pkg) {
        if (pkg == null || pkg.isEmpty()) return null;
        return getContext().getPackageManager().getLaunchIntentForPackage(pkg);
    }
}
