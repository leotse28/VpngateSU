package io.github.leotse28.vpngatesu

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle

class MainActivity : ComponentActivity() {

    private val vm: VpnGateViewModel by viewModels()

    private val requestNotificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* denied: the foreground notification simply won't show */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
        ) {
            requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        setContent {
            MaterialTheme {
                VpnGateApp(vm, ::onConnectionChanged)
            }
        }
    }

    /** Mirrors ViewModel connection state into the foreground service. */
    private var serviceRunning = false

    private fun onConnectionChanged(connected: Boolean, state: UiState) {
        if (connected && !serviceRunning) {
            val intent = Intent(this, ProxyService::class.java)
                .setAction(ProxyService.ACTION_START)
                .putExtra(ProxyService.EXTRA_HOST, state.connectedHost ?: "")
                .putExtra(ProxyService.EXTRA_VIP, state.vip ?: "")
                .putExtra(ProxyService.EXTRA_LISTEN, state.listenAddr ?: "")
            ContextCompat.startForegroundService(this, intent)
            serviceRunning = true
        } else if (!connected && serviceRunning) {
            stopService(Intent(this, ProxyService::class.java))
            serviceRunning = false
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VpnGateApp(vm: VpnGateViewModel, onConnectionChanged: (Boolean, UiState) -> Unit) {
    val state by vm.state.collectAsStateWithLifecycle()
    var tab by remember { mutableIntStateOf(0) }

    LaunchedEffect(state.connected, state.connectedHost) {
        onConnectionChanged(state.connected, state)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text("VpngateSU" + (state.coreVersion?.let { " · core $it" } ?: ""))
                }
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = tab == 0, onClick = { tab = 0 },
                    icon = {}, label = { Text("节点") },
                )
                NavigationBarItem(
                    selected = tab == 1, onClick = { tab = 1 },
                    icon = {}, label = { Text("设置") },
                )
                NavigationBarItem(
                    selected = tab == 2, onClick = { tab = 2 },
                    icon = {}, label = { Text("日志") },
                )
            }
        }
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(12.dp)
        ) {
            state.error?.let {
                Text(it, color = Color.Red, modifier = Modifier.padding(bottom = 8.dp))
                OutlinedButton(onClick = vm::clearMessage) { Text("清除") }
            }
            state.notice?.let {
                Text(it, modifier = Modifier.padding(bottom = 8.dp))
            }
            if (state.busy) {
                Text(state.busyLabel, modifier = Modifier.padding(bottom = 8.dp))
            }
            when (tab) {
                0 -> NodesTab(vm, state)
                1 -> SettingsTab(vm, state)
                2 -> LogTab(vm, state)
            }
        }
    }
}

@Composable
fun NodesTab(vm: VpnGateViewModel, state: UiState) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            if (state.connected) {
                Text("已连接：${state.connectedHost ?: ""}")
                Text("出口 IP：${state.vip ?: ""}")
                Text("本地代理：${state.listenAddr ?: ""}")
                Text("隧道会话：${state.sessions} 个" + if (!state.alive) "（隧道已断开）" else "")
                Spacer(Modifier.height(8.dp))
                Button(onClick = vm::disconnect) { Text("断开") }
            } else {
                Text("未连接")
                Text("选一个节点再点连接；连上后把 Wi-Fi 代理设为本地代理地址。")
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = vm::connect,
                    enabled = state.selectedHost != null && !state.busy,
                ) { Text("连接选中节点") }
            }
        }
    }
    Spacer(Modifier.height(8.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = { vm.refresh(false) }, enabled = !state.busy) { Text("刷新节点") }
        OutlinedButton(onClick = { vm.refresh(true) }, enabled = !state.busy) { Text("从 API 刷新节点") }
    }
    Spacer(Modifier.height(8.dp))
    Text(state.nodesLabel.ifEmpty { "节点列表为空" })
    Text("共 ${state.nodes.size} 个节点（点一行选中）")
    Spacer(Modifier.height(8.dp))
    LazyColumn(Modifier.fillMaxSize()) {
        items(state.nodes, key = { it.host }) { node ->
            Column(
                Modifier
                    .fillMaxWidth()
                    .clickable { vm.selectNode(node.host) }
                    .padding(vertical = 6.dp)
            ) {
                Text(
                    "${if (node.host == state.selectedHost) "● " else ""}${node.country} ${node.isp} · ${node.hostPort}",
                    color = if (node.host == state.selectedHost) MaterialTheme.colorScheme.primary
                    else Color.Unspecified,
                )
                Text(
                    "人数 ${if (node.sessions == 0L) "—" else node.sessions} · " +
                        "速度 ${if (node.speed_mbps == 0L) "—" else "${node.speed_mbps} Mbps"} · " +
                        "端口 ${node.displayPort}（${node.port_source}）",
                    fontSize = 13.sp,
                )
            }
        }
    }
}

@Composable
fun SettingsTab(vm: VpnGateViewModel, state: UiState) {
    val settings = state.settings
    var frontEnabled by remember(settings) { mutableStateOf(settings.frontEnabled) }
    var frontAddr by remember(settings) { mutableStateOf(settings.frontAddr) }
    var listenAddr by remember(settings) { mutableStateOf(settings.listenAddr) }
    var localPort by remember(settings) { mutableStateOf(settings.localPort.toString()) }
    var allowLan by remember(settings) { mutableStateOf(settings.allowLan) }
    var timeoutSecs by remember(settings) { mutableStateOf(settings.timeoutSecs.toString()) }
    val activity = androidx.compose.ui.platform.LocalContext.current as ComponentActivity

    Column(Modifier.verticalScroll(rememberScrollState())) {
        Text("前置代理（手机上跑 v2rayNG / NekoBox Android，本地 SOCKS5 接同一条 VLESS 节点）")
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("启用前置代理", Modifier.weight(1f))
            Switch(checked = frontEnabled, onCheckedChange = { frontEnabled = it })
        }
        OutlinedTextField(
            value = frontAddr, onValueChange = { frontAddr = it },
            label = { Text("前置代理地址（默认 127.0.0.1:10808）") },
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(12.dp))
        Text("本地代理（手机 Wi-Fi 设置里填这个地址）")
        OutlinedTextField(
            value = listenAddr, onValueChange = { listenAddr = it },
            label = { Text("监听地址（默认 127.0.0.1）") },
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = localPort,
            onValueChange = { localPort = it.filter(Char::isDigit) },
            label = { Text("本地端口（默认 10818）") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("局域网共享（绑 0.0.0.0，代理填手机 Wi-Fi IP）", Modifier.weight(1f))
            Switch(checked = allowLan, onCheckedChange = { allowLan = it })
        }
        OutlinedTextField(
            value = timeoutSecs,
            onValueChange = { timeoutSecs = it.filter(Char::isDigit) },
            label = { Text("隧道超时（秒，默认 10）") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(12.dp))
        Button(
            onClick = {
                vm.saveSettings(
                    AppSettings(
                        frontEnabled = frontEnabled,
                        frontAddr = frontAddr.trim(),
                        listenAddr = listenAddr.trim(),
                        localPort = localPort.toIntOrNull() ?: 10818,
                        allowLan = allowLan,
                        timeoutSecs = timeoutSecs.toLongOrNull() ?: 10,
                    )
                )
            },
            enabled = !state.busy,
        ) { Text("保存设置") }
        Spacer(Modifier.height(12.dp))
        OutlinedButton(
            onClick = {
                runCatching {
                    activity.startActivity(
                        Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                    )
                }
            }
        ) { Text("请求忽略电池优化（保活）") }
        Spacer(Modifier.height(12.dp))
        Text(
            "注意：Wi-Fi 代理只对该 Wi-Fi 网络生效；只有听从系统代理设置的 app 才走隧道；" +
                "UDP 不进 Wi-Fi HTTP 代理（QUIC 可能直连）。断开后已设代理的 app 会直接连不上，" +
                "这是预期的（不是悄悄直连）。个别机型不接受 127.0.0.1 作代理地址时，" +
                "开局域网共享、代理填手机的 Wi-Fi IP。",
            fontSize = 13.sp,
        )
    }
}

@Composable
fun LogTab(vm: VpnGateViewModel, state: UiState) {
    Button(onClick = vm::refreshLogs) { Text("刷新日志") }
    Spacer(Modifier.height(8.dp))
    Text("日志文件：filesDir/vpngate-gui.log（与桌面版同格式，2 MB 轮转）", fontSize = 13.sp)
    Spacer(Modifier.height(8.dp))
    LazyColumn(Modifier.fillMaxSize()) {
        items(state.logLines) { line ->
            Text(line, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
        }
    }
}
