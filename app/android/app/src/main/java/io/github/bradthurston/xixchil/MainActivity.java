package io.github.bradthurston.xixchil;

import android.content.Intent;
import android.os.Bundle;

import com.getcapacitor.BridgeActivity;

/**
 * The app's entry point, extended for one reason: a capture can arrive from outside it.
 *
 * "Share → Xixchil", or opening a .22000 / .pcap from a file manager, delivers the
 * file as an intent. Both a cold start (onCreate) and a share into the running app
 * (onNewIntent — the activity is singleTask, so Android reuses it) are stashed for the
 * plugin to hand to JS. Nothing is parsed here; this only makes sure the file is not
 * dropped on the floor before the app is ready to read it.
 */
public class MainActivity extends BridgeActivity {

    @Override
    public void onCreate(Bundle savedInstanceState) {
        // Before super.onCreate: Capacitor collects plugins during it, so a plugin
        // registered afterwards is not reachable from JS.
        registerPlugin(CaptureImportPlugin.class);
        registerPlugin(AppLauncherPlugin.class);
        super.onCreate(savedInstanceState);
        CaptureImportPlugin.stash(this, getIntent());
    }

    @Override
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        CaptureImportPlugin.stash(this, intent);
    }
}
