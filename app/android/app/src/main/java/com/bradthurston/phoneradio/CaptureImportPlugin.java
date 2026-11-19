package com.bradthurston.phoneradio;

import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.util.Base64;
import android.util.Log;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * The phone's door for a capture shared from another app.
 *
 * Android hands a shared file to the activity as a content:// URI, not a path, and the
 * read grant on that URI is temporary. So the intent is stashed the moment it arrives
 * (possibly before any WebView exists) and the bytes are read later, when JS asks.
 *
 * The plugin deliberately does no parsing: it moves bytes and reports what the file was
 * called. Everything about formats lives in one place, in the app's own importer, so a
 * shared capture and a picked one cannot diverge.
 *
 * Reads are capped: a file larger than the cap is refused with a reason rather than
 * filling the phone's memory with a base64 string.
 */
@CapacitorPlugin(name = "CaptureImport")
public class CaptureImportPlugin extends Plugin {

    private static final String TAG = "RadioConsole";

    /** Refuse anything bigger. Portal exports are kilobytes; captures are megabytes. */
    private static final long MAX_BYTES = 32L * 1024 * 1024;

    // Static: the intent arrives on the activity, before the bridge that would own an
    // instance of this plugin exists. One process, one pending share at a time.
    private static Uri pendingUri = null;
    private static String pendingName = null;

    /**
     * Remember a shared or opened file. Called from MainActivity for both a cold start
     * (onCreate) and a share into the running app (onNewIntent).
     */
    static void stash(Context ctx, Intent intent) {
        if (intent == null) return;

        final String action = intent.getAction();
        Uri uri = null;
        if (Intent.ACTION_SEND.equals(action)) {
            uri = intent.getParcelableExtra(Intent.EXTRA_STREAM);
        } else if (Intent.ACTION_VIEW.equals(action)) {
            uri = intent.getData();
        }
        if (uri == null) return;

        pendingUri = uri;
        pendingName = displayName(ctx, uri);
        Log.i(TAG, "capture shared in: " + uri + " (" + pendingName + ")");
    }

    /** The file's own name if the provider offers one, else its last path segment. */
    private static String displayName(Context ctx, Uri uri) {
        Cursor c = null;
        try {
            c = ctx.getContentResolver().query(uri, new String[] { OpenableColumns.DISPLAY_NAME },
                    null, null, null);
            if (c != null && c.moveToFirst()) {
                int i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (i >= 0) {
                    String n = c.getString(i);
                    if (n != null && !n.isEmpty()) return n;
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "could not read the shared file's name", e);
        } finally {
            if (c != null) c.close();
        }
        String last = uri.getLastPathSegment();
        return last != null && !last.isEmpty() ? last : "shared-capture";
    }

    /**
     * Hand the pending share to JS and clear it, so one share is imported once.
     * Resolves { pending: false } when there is nothing waiting.
     */
    @PluginMethod
    public void getPending(PluginCall call) {
        JSObject out = new JSObject();

        Uri uri = pendingUri;
        if (uri == null) {
            out.put("pending", false);
            call.resolve(out);
            return;
        }
        pendingUri = null;                                  // consumed either way
        String name = pendingName != null ? pendingName : "shared-capture";
        pendingName = null;

        try {
            byte[] bytes = readAll(uri);
            out.put("pending", true);
            out.put("name", name);
            out.put("size", bytes.length);
            out.put("base64", Base64.encodeToString(bytes, Base64.NO_WRAP));
            call.resolve(out);
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            Log.w(TAG, "could not read the shared capture: " + msg);
            // Reported, not swallowed: the app shows the reason instead of doing nothing.
            out.put("pending", false);
            out.put("error", msg);
            call.resolve(out);
        }
    }

    private byte[] readAll(Uri uri) throws Exception {
        InputStream in = null;
        try {
            in = getContext().getContentResolver().openInputStream(uri);
            if (in == null) throw new Exception("the shared file could not be opened");

            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[64 * 1024];
            long total = 0;
            int n;
            while ((n = in.read(chunk)) > 0) {
                total += n;
                if (total > MAX_BYTES) {
                    throw new Exception("the shared file is larger than " + (MAX_BYTES / (1024 * 1024)) + " MB");
                }
                buf.write(chunk, 0, n);
            }
            return buf.toByteArray();
        } finally {
            if (in != null) {
                try { in.close(); } catch (Exception ignored) { }
            }
        }
    }
}
