package io.github.leotse28.vpngatesu

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import java.io.File

data class UiState(
    val initialised: Boolean = false,
    val coreVersion: String? = null,
    val nodes: List<NodeDto> = emptyList(),
    val nodesLabel: String = "",
    val selectedHost: String? = null,
    val connected: Boolean = false,
    val connectedHost: String? = null,
    val vip: String? = null,
    val sessions: Int = 0,
    val listenAddr: String? = null,
    val alive: Boolean = false,
    val settings: AppSettings = AppSettings(),
    val logLines: List<String> = emptyList(),
    val busy: Boolean = false,
    val busyLabel: String = "",
    val error: String? = null,
    val notice: String? = null,
)

/**
 * Single ViewModel for Phase A. All NativeBridge calls are blocking
 * JNI, so they run on Dispatchers.IO. The Rust .so owns the
 * connection; this layer only mirrors its JSON into StateFlow.
 */
class VpnGateViewModel(application: Application) : AndroidViewModel(application) {

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    init {
        viewModelScope.launch(Dispatchers.IO) {
            val filesDir = getApplication<Application>().filesDir
            val initJson = NativeBridge.nativeInit(filesDir.absolutePath)
            val init = runCatching { AppJson.decodeFromString<ConfigResponse>(initJson) }.getOrNull()
            if (init == null || !init.ok) {
                _state.update {
                    it.copy(error = init?.error ?: "初始化失败：无法解析 nativeInit 返回")
                }
                return@launch
            }
            // First run: no config.toml yet — write the phone defaults
            // (front proxy 127.0.0.1:10808 for v2rayNG/NekoBox Android)
            // so the Rust default (desktop 1080) never surfaces.
            var settings = init.config ?: AppSettings()
            if (!File(filesDir, "config.toml").exists()) {
                val saved = runCatching {
                    AppJson.decodeFromString<ConfigResponse>(
                        NativeBridge.nativeSaveConfig(AppJson.encodeToString(AppSettings()))
                    )
                }.getOrNull()
                if (saved?.ok == true && saved.config != null) settings = saved.config
            }
            _state.update {
                it.copy(initialised = true, settings = settings, coreVersion = init.coreVersion)
            }
            loadCachedNodes()
            refreshLogs()
            // Poll the tunnel while connected: sessions count + liveness.
            // If the tunnel dies, the state flips and MainActivity
            // stops the foreground service.
            while (true) {
                delay(3000)
                if (_state.value.connected) pollStatus()
            }
        }
    }

    fun selectNode(host: String) {
        _state.update { it.copy(selectedHost = host) }
    }

    fun clearMessage() {
        _state.update { it.copy(error = null, notice = null) }
    }

    fun refresh(apiOnly: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.update {
                it.copy(busy = true, busyLabel = if (apiOnly) "正在从 API 刷新…" else "正在刷新节点…", error = null, notice = null)
            }
            val resp = runCatching {
                AppJson.decodeFromString<NodesResponse>(NativeBridge.nativeRefreshNodes(apiOnly))
            }.getOrNull()
            _state.update { s ->
                when {
                    resp == null -> s.copy(busy = false, error = "刷新失败：无法解析返回")
                    !resp.ok -> s.copy(busy = false, error = resp.error ?: "刷新失败")
                    else -> s.copy(
                        busy = false,
                        nodes = resp.nodes,
                        nodesLabel = resp.label ?: "",
                        notice = resp.label,
                    )
                }
            }
        }
    }

    fun connect() {
        val node = _state.value.nodes.firstOrNull { it.host == _state.value.selectedHost }
            ?: run {
                _state.update { it.copy(error = "请先在列表里选一个节点") }
                return
            }
        viewModelScope.launch(Dispatchers.IO) {
            _state.update { it.copy(busy = true, busyLabel = "正在连接 ${node.hostPort}…", error = null, notice = null) }
            val resp = runCatching {
                AppJson.decodeFromString<ConnectResponse>(
                    NativeBridge.nativeConnect(node.host, node.port ?: 0)
                )
            }.getOrNull()
            _state.update { s ->
                when {
                    resp == null -> s.copy(busy = false, error = "连接失败：无法解析返回")
                    !resp.ok -> s.copy(busy = false, error = resp.error ?: "连接失败")
                    else -> s.copy(
                        busy = false,
                        connected = true,
                        connectedHost = resp.host ?: node.host,
                        vip = resp.vip,
                        listenAddr = resp.listenAddr,
                        sessions = 0,
                        alive = true,
                        notice = "已连接 ${resp.host ?: node.host}，出口 ${resp.vip}",
                    )
                }
            }
        }
    }

    fun disconnect() {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { NativeBridge.nativeDisconnect() }
            _state.update {
                it.copy(
                    connected = false, connectedHost = null, vip = null,
                    sessions = 0, listenAddr = null, alive = false,
                    notice = "已断开",
                )
            }
        }
    }

    fun saveSettings(settings: AppSettings) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.update { it.copy(busy = true, busyLabel = "正在保存设置…", error = null, notice = null) }
            val resp = runCatching {
                AppJson.decodeFromString<ConfigResponse>(
                    NativeBridge.nativeSaveConfig(AppJson.encodeToString(settings))
                )
            }.getOrNull()
            _state.update { s ->
                when {
                    resp == null -> s.copy(busy = false, error = "保存失败：无法解析返回")
                    !resp.ok -> s.copy(busy = false, error = resp.error ?: "保存失败")
                    resp.config != null -> s.copy(busy = false, settings = resp.config, notice = "设置已保存")
                    else -> s.copy(busy = false, notice = "设置已保存")
                }
            }
        }
    }

    fun refreshLogs() {
        viewModelScope.launch(Dispatchers.IO) {
            val resp = runCatching {
                AppJson.decodeFromString<LogsResponse>(NativeBridge.nativeGetLogs())
            }.getOrNull()
            if (resp?.ok == true) {
                _state.update { it.copy(logLines = resp.lines) }
            }
        }
    }

    private fun loadCachedNodes() {
        val resp = runCatching {
            AppJson.decodeFromString<NodesResponse>(NativeBridge.nativeLoadCachedNodes())
        }.getOrNull()
        if (resp?.ok == true) {
            _state.update { it.copy(nodes = resp.nodes, nodesLabel = resp.label ?: "") }
        }
    }

    private fun pollStatus() {
        val resp = runCatching {
            AppJson.decodeFromString<StatusResponse>(NativeBridge.nativeGetStatus())
        }.getOrNull() ?: return
        if (!resp.ok) return
        _state.update { s ->
            if (!resp.connected) {
                s.copy(connected = false, connectedHost = null, vip = null, sessions = 0, listenAddr = null, alive = false)
            } else {
                s.copy(
                    connectedHost = resp.host ?: s.connectedHost,
                    vip = resp.vip ?: s.vip,
                    sessions = resp.sessions,
                    listenAddr = resp.listenAddr ?: s.listenAddr,
                    alive = resp.alive,
                )
            }
        }
    }
}
