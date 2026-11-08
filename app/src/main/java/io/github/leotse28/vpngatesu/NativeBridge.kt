package io.github.leotse28.vpngatesu

/**
 * Thin JNI boundary to the Rust core (rust/jni, cdylib
 * `libvpngatesu_jni.so`). Every call returns one JSON string; errors
 * are `{"ok":false,"error":"..."}`. All calls are blocking — call
 * them from Dispatchers.IO, never on the main thread.
 */
object NativeBridge {
    init {
        System.loadLibrary("vpngatesu_jni")
    }

    /** Initialise the tokio runtime + file log. Returns config JSON. */
    external fun nativeInit(filesDir: String): String

    external fun nativeGetConfig(): String

    /** Partial settings JSON; missing fields keep their current value. */
    external fun nativeSaveConfig(json: String): String

    /** apiOnly=false: API → web → cache → curated. true: API only. */
    external fun nativeRefreshNodes(apiOnly: Boolean): String

    /** Startup list: cache if present, else the bundled curated list. */
    external fun nativeLoadCachedNodes(): String

    /** port<=0: resolve via the curated table / candidate ports. */
    external fun nativeConnect(host: String, port: Int): String

    external fun nativeDisconnect(): String

    external fun nativeGetStatus(): String

    /** Tail of filesDir/vpngate-gui.log (last 200 lines). */
    external fun nativeGetLogs(): String

    external fun nativeGetVersion(): String
}
