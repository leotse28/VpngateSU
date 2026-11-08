package io.github.leotse28.vpngatesu

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Lenient JSON: the Rust side may add fields later. */
val AppJson = Json { ignoreUnknownKeys = true }

/** One VPNGate node, as serialised by the Rust core (serde field names). */
@Serializable
data class NodeDto(
    val host: String,
    val port: Int? = null,
    val country: String = "",
    val country_code: String = "",
    val isp: String = "",
    val name: String = "",
    val score: Long = 0,
    val ping_ms: Long = 0,
    val speed_mbps: Long = 0,
    val sessions: Long = 0,
    val ip: String = "",
    val backups: List<String> = emptyList(),
    val port_source: String = "",
    val source: String = "",
) {
    /** `host:port`, or the bare host when the SSTP port is unknown. */
    val hostPort: String get() = if (port != null) "$host:$port" else host
    val displayPort: String get() = port?.toString() ?: "?"
}

/**
 * Settings the user edits. This is the Kotlin view of the Rust
 * `Config` (config.toml in filesDir); the .so is the source of truth
 * and Kotlin defaults only apply before the first load. The front
 * proxy default (127.0.0.1:10808, v2rayNG/NekoBox Android) differs
 * from the desktop default (1080) on purpose — see DESIGN.md §4.3.
 */
@Serializable
data class AppSettings(
    val frontEnabled: Boolean = false,
    val frontAddr: String = "127.0.0.1:10808",
    val listenAddr: String = "127.0.0.1",
    val localPort: Int = 10818,
    val allowLan: Boolean = false,
    val timeoutSecs: Long = 10,
)

@Serializable
data class ConfigResponse(
    val ok: Boolean,
    val config: AppSettings? = null,
    val already: Boolean = false,
    val coreVersion: String? = null,
    val error: String? = null,
)

@Serializable
data class NodesResponse(
    val ok: Boolean,
    val nodes: List<NodeDto> = emptyList(),
    val source: String? = null,
    val label: String? = null,
    val apiError: String? = null,
    val webError: String? = null,
    val error: String? = null,
)

@Serializable
data class ConnectResponse(
    val ok: Boolean,
    val vip: String? = null,
    val listenAddr: String? = null,
    val host: String? = null,
    val error: String? = null,
)

@Serializable
data class StatusResponse(
    val ok: Boolean,
    val connected: Boolean = false,
    val host: String? = null,
    val port: Int? = null,
    val vip: String? = null,
    val sessions: Int = 0,
    val listenAddr: String? = null,
    val alive: Boolean = false,
    val error: String? = null,
)

@Serializable
data class LogsResponse(
    val ok: Boolean,
    val lines: List<String> = emptyList(),
    val droppedConnLog: Int = 0,
    val error: String? = null,
)

@Serializable
data class SimpleResponse(
    val ok: Boolean,
    val error: String? = null,
)
