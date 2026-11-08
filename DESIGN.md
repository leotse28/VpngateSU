# VpngateSU 设计文档

- 状态：阶段 0（学习与设计）完成，等待进入阶段 2（动手写移植代码）
- 移植 base：VPNGATE-LITE v3.16，commit `54bf0ad50d9ded6e25c6a7413ae1e8c61ad1ddb4`（main head，2026-11-08）
- 参考实现：`~/workspace/vpngate-rust-client/`，仓库 `leotse28/VPNGATE-LITE`
- 目标产物：Android 11+（minSdk 30）可安装的 APK；新库名 `VpngateSU`（Leo 建空库并授权后才 push）
- 依据的 skill：`userspace-vpn-client`（系统工程）+ `android-dev`（Android 开发，见 §1）

## 0. 目标与非目标

目标：把 VPNGATE-LITE 的能力搬到 Leo 的 Android 手机上——同一套节点列表、同一条 MS-SSTP 隧道、同一个本地混合代理端口、同一条前置代理链，最终形态是一个能装到 Android 11+ 手机上的 APK。

非目标（和 Rust 版一致，Leo 定下的线）：

- 不做 VpnService / TUN / 虚拟网卡，不改路由表，不做全局 VPN。只做 port-proxy。
- 不做 OpenVPN 协议实现（userspace-vpn-client skill 明确排除；之前两次被安全检查拒绝，不重试）。
- 阶段 0 不写移植代码；阶段 2 才动手。

## 1. 依据的 skill（阶段 0 已装）

### 1.1 userspace-vpn-client（系统工程）

已读 `~/workspace/custom-skills/userspace-vpn-client/SKILL.md`。本设计沿用它的架构约束与发布流程：

- 架构：本地混合代理（SOCKS5+HTTP CONNECT+普通 HTTP，单端口）→ 用户态 TCP/UDP 栈 → SSTP+PPP 隧道 → 可选 SOCKS5 前置代理链；节点列表四级兜底（官方 API → 网页抓取 → 本地缓存 → 内嵌列表）。
- 流程：一个版本一个主题 → 实现+测试 → 交叉编译 → push → Release → 用户在真机上验证、回传日志 → 下一版。VM 验证不了的东西如实写进测试报告，不谎称已验证。
- 诊断方法：先数数再下结论；日志行要写明来源与数字；截图看状态、日志看机制。

### 1.2 android-dev（Android 开发）

本地原来没有 Android 开发 skill（`muse.skill_search` 查过，只有 `app-creation` 这种做网页 artifact 的，不适用）。网上找了一圈，结论：

- 官方 Google Android 团队的 `android/skills`（https://github.com/android/skills，Apache-2.0，~10.4k stars）是模块化任务 skill 库（CameraX、Navigation、R8、Edge-to-Edge、Profiler 等），README 明确说了：**不做通用开发 skill**——基础 Compose 这类 LLM 本来就会的领域他们故意不做。所以它不能作为主 skill；阶段 2 如需 AGP 升级或测试搭建方面的指引，可再从里面取 `build-system/agp/agp-9-upgrade`、`testing/testing-setup` 这两个作补充。
- 最贴合的是 `Quad4-Software/skills` 里的 `android-dev`：Kotlin + Gradle KTS + Jetpack Compose，覆盖项目布局、版本目录、**build/test/install/verify loop（adb）**、Compose 约定、常见编译错误。已原样装到 `~/workspace/custom-skills/android-dev/`（SKILL.md + references/adb-and-build.md，12K，无二进制、无 secrets；来源提交 `6d4dfc6527e8bb1fa35f6c90c4d4e01b838f8721`，0BSD 许可），`muse.skill_search` 已能检索到 `android_dev`。
- 它的工具链快照（构建时再核对一次）：Kotlin 2.4.x、AGP 9.4.x、Gradle 9.6+、JVM 17；compileSdk 37、targetSdk 36+（Google Play 2026-08-31 起要求新应用 targetSdk 36+）；单 `:app` 模块、版本目录 `gradle/libs.versions.toml`。minSdk 它给的是 26（媒体类应用的底线），我们按 Leo 的要求取 **30**。

## 2. 决定一：移植路线——Rust 核心经 NDK/JNI 复用 + Kotlin 界面

**选择：不重写，复用。** Rust 核心（SSTP/PPP、用户态 TCP/UDP、混合代理、节点拉取、DoH、探测）是经过 v3.1–v3.16 十几版日志验证的资产；用 Kotlin 重写等于把协议逻辑重新实现一遍，还会和 Rust 版分叉。Kotlin 只写界面与 Android 外壳（Service、通知、设置、文件访问），通过 JNI 调核心。

**核心已有的、可直接用的公开接口（v3.16 代码中核实）：**

| 能力 | Rust 侧现成的入口 |
|---|---|
| 本地混合代理服务 | `socks5::serve_mixed(listener, tunnel, timeout, conn_log)`（入参是已绑好的 TcpListener + 已连好的隧道） |
| 建隧道 / 探测 | `sstp::SstpClient::connect_any`、`probe_any`、`probe`、`open_stream`、`open_udp_flow`、`send_udp`、`close_udp_flow` |
| 节点拉取 | `vpngate::fetch_nodes_with_fallback`（API → 网页 → 缓存 → 内嵌）、`fetch_api_only`（v3.15 的纯 API 档）、`parse_api_csv`、`parse_web_page` |
| 缓存 | `save_cached_nodes_to(path, …)`（显式路径版；无路径版 `save_cached_nodes` 走 exe 旁，Android 上不用） |
| 配置 | `config::Config::load(Some(path))` / `save(&self, path)`（都接受显式路径） |
| 日志 | `filelog`（路径需在 JNI 初始化时显式指定，见 §5） |

**JNI 边界（阶段 2 再定最终签名，原则）：** 薄而小，JSON 进出 + 日志回调，例如初始化（传 filesDir 路径）、启动/停止本地代理、连接/断开节点、刷新节点、探测、取状态 JSON、取日志行。tokio runtime 在 `.so` 内初始化一次；JNI 调用线程进出 runtime 时按 JNI 规范 attach/detach。

**前置任务（阶段 2 动手前必须先做）：把 GUI 依赖从 lib 里解耦。** 核实到的问题：`src/tray.rs` 是 lib 模块（`src/lib.rs` 无条件 `pub mod tray`），它引用 eframe，而 `[dependencies]` 里 eframe 0.36、rfd、arboard 是整个 lib 的依赖。Android 的 `.so` 不需要、也不应该链进一整套桌面 GUI 库（winit/wgpu）。做法：把 tray 及 eframe/rfd/arboard 移到 feature 门之后（例如 `gui` feature，默认开，Android 构建时关掉），或移入 GUI bin；改完 Rust 版 `cargo test` 与 Windows 交叉编译仍要全过，再开始 Android 构建。

**构建方式：** `cargo build --target aarch64-linux-android` + NDK clang（或 cargo-ndk，二选一，阶段 2 定），产物 `.so` 放 `app/src/main/jniLibs/arm64-v8a/`。ABI 首发只做 **arm64-v8a**（Leo 的手机几乎一定是 arm64；阶段 2 用 `adb shell getprop ro.product.cpu.abi` 核对一次）；armeabi-v7a 延后，不阻塞第一版。

**代价（写清楚）：** JNI 调试比纯 Kotlin 难；`.so` 体积大；tokio + JNI 的线程与生命周期要小心；每次 Rust 核心改动都要重新编 `.so`。但比起重写协议栈，这些代价小得多。

## 3. 决定二：Port-proxy only，不做 VpnService/TUN；手机经 Wi-Fi HTTP 代理用它

**选择：Android 端同样只做本地代理，不碰 VpnService。** 理由一半是 Leo 定下的线（无虚拟网卡、不改路由、不做全局 VPN），一半是代码已经支持这条路——核实过，不是假设。

**已在代码中核实的关键点（`src/socks5.rs`，`http_target` 函数）：** 混合端口的 HTTP 侧同时处理三种形式——`CONNECT host:443`（默认 443）、绝对形式 `http://host[:port]/…`（默认 80）、起源形式 `/path…` + Host 头（默认 80）。这正是 Android Wi-Fi 代理发出的两种形式（http 走绝对形式，https 走 CONNECT）。所以手机用法是：

1. VpngateSU 在本机起混合代理，例如 `127.0.0.1:10818`（端口与 Rust 版一致，用户可改）。
2. 用户在该 Wi-Fi 网络的设置里把代理设为 `127.0.0.1:10818`，手机浏览器与听从系统代理的 app 走隧道。

**这条路的诚实边界（写进 README 与真机清单，不藏着）：**

- Wi-Fi 代理只对**该 Wi-Fi 网络**生效；切到移动数据就不走代理了。
- 只有听从系统代理设置的 app 才走隧道；不听代理设置的 app 直接直连。
- **UDP 不进 Wi-Fi HTTP 代理。** 但 https 不受影响——CONNECT 里带的是域名，由代理侧（经隧道内的 DoH / 解析）解析，不由手机 DNS 解析；可能直连的是 QUIC（UDP 443），和 PC 上 Chrome 的 QUIC 直连是同款问题，办法一样：关 QUIC 或接受它。
- 没有按 app 分流，没有 kill switch。断开隧道时，已设代理的 app 会直接连不上（而不是悄悄直连）——这是预期行为，要在界面里写明。
- 核心里的 SOCKS5 UDP ASSOCIATE 中继仍在（`serve_mixed` 会在同一端口绑 UDP，绑不上时 TCP 照常工作、UDP 明确报错），但 Wi-Fi 代理路径用不到它；它留给将来本机上的 SOCKS5 消费者（例如应用内嵌的组件），不是第一版的卖点。
- **回退：** 个别 OEM 不接受 `127.0.0.1` 作 Wi-Fi 代理地址。核心已支持绑 `0.0.0.0`（Rust 版局域网共享就是同一套，`Config::listen_addrs`），回退方案是绑 `0.0.0.0`、代理地址填手机的 Wi-Fi IP（例如 192.168.1.x）。阶段 2 在界面里把两种地址都显示出来。

**不在 Android 上做的东西：** 系统代理开关（Android 没有 PC 那种全局代理 toggle，Rust 版 `sysproxy.rs` 在非 Windows/macOS 上本来就是 no-op 分支，Android 上不要调它）；托盘；单实例（Android 单进程，不需要 `single_instance.rs` 那套）；Ctrl+A 这类桌面交互。

## 4. 决定三：前台 Service 保活 + 应用私有目录存配置 + 前置代理用手机上的 VLESS 客户端

### 4.1 前台 Service

Android 会杀后台进程，一个本地代理服务必须以前台 Service 跑：常驻通知 + `foregroundServiceType="dataSync"`（构建时按现行文档核对类型是否恰当）+ `FOREGROUND_SERVICE_DATA_SYNC`（API 34+）。Service 内跑 tokio runtime 与 `serve_mixed`；用户点连接才启动 Service（前台启动，合规）；通知里放断开按钮。另需引导用户开电池优化豁免（`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` 意图，侧载可用；Doze 仍可能影响，要在真机清单里验）。

重启行为与 Rust 版**不**对齐：Rust 版“重启客户端后自动连回”是托盘特有的，Android 上不等价。v1 只做手动：Service 被杀后不自动重连，用户在通知或界面里点“重新连接”。

### 4.2 存储：应用私有目录

exe 旁放文件那套在 Android 上不存在。改放 `Context.getFilesDir()`：`config.toml`、`nodes_cache.json`、日志文件。格式与 Rust 版**完全相同**（TOML / JSON），Leo 可以在 PC 与手机之间互拷。JNI 初始化时显式传路径：`Config::load(Some(path))`、`save_cached_nodes_to(path)`、filelog 路径——不要用 `Config::portable_dir()`（它找 exe 所在目录）。UI 偏好（主题之类）用 DataStore；节点与连接配置坚持走 TOML/JSON 文件，与 PC 保持互通。

导出/导入沿用 v3.16 的 6 列 TSV（`主机:端口\t国家\t运营商\t当前人数\t速度\t探测延时`，第 6 列是毫秒整数、没测过为空；导入恢复进 probe_ms；老 5 列文件仍能导入；**重复主机整行跳过、不覆盖已有的 probe_ms**——v3.16 已确认的行为，Android 端保持一致）。Android 上经 SAF（Storage Access Framework）选文件，或走系统分享。probe_ms 在 Android 端同样只是内存态，重启后丢，与 Rust 版一致。

### 4.3 前置代理在手机上怎么接

PC 上的 NekoBox（`127.0.0.1:2080`）在手机上不存在。两条路：

- **首选（手机原生）：** 手机上跑 v2rayNG / NekoBox Android，本地 SOCKS5（例如 `127.0.0.1:10808`）接同一条 Cloady VLESS 节点；VpngateSU 的前置代理指向它。核心的 Connector 已支持前置 SOCKS5（拉取、DoH、探测、连接全走它），不需要新代码。
- **备选（经 PC）：** PC 的 NekoBox SOCKS5 开局域网共享，手机上填 PC 的局域网 IP:2080。能用，但手机离开家里 Wi-Fi 就断，只作备选。

## 5. 目标版本与权限

- **minSdk 30（Android 11）**，targetSdk 36，compileSdk 37。Kotlin 2.4.x、AGP 9.4.x、Gradle 9.6+、JDK 17（android-dev skill 的快照，构建时再核对一次；版本不存在或下不到就退到当时最新的稳定版）。不走 Play（侧载），但 targetSdk 仍取 36。
- 权限清单：`INTERNET`（必须，含 localhost socket）、`ACCESS_NETWORK_STATE`、`FOREGROUND_SERVICE`、`FOREGROUND_SERVICE_DATA_SYNC`（API 34+）、`POST_NOTIFICATIONS`（API 33+，运行时申请，否则常驻通知不显示）。
- 不需要：`BIND_VPN_SERVICE`（不用 VpnService）、位置权限、存储权限（私有目录 + SAF，不用外部存储权限）。`RECEIVE_BOOT_COMPLETED`：v1 不做开机自启，不声明；以后要加再说。

## 6. 界面与功能范围（分三步交付）

Kotlin + Jetpack Compose，单 `:app` 模块，ViewModel + StateFlow，版本目录 `gradle/libs.versions.toml`（按 android-dev skill 的布局）。

- **Phase A（第一个 APK）：** 节点列表（缓存/API 刷新）、连接/断开、前置代理与本地端口设置、日志查看、状态通知。目标：assemble 成功、装得上、连上一个节点、手机浏览器经 Wi-Fi 代理能打开网页。
- **Phase B：** 探测全部（延时排序）、导出/导入（6 列 TSV）、屏蔽列表、按节点状态显示。
- **Phase C：** 通知栏操作、开机自启（可选）、release 签名与打包。

## 7. 构建与验证（VM 现状，2026-11-08 核实）

- VM 里现状：**无 Android SDK、无 JDK、无 adb**，`ANDROID_HOME` 为空。Rust 工具链在 `~/.cargo/bin`（`PATH` 里没有，构建时要加上；已装 target 只有 `x86_64-pc-windows-gnu` 与 `x86_64-unknown-linux-gnu`）。
- 阶段 2 要装：JDK 17、Android cmdline-tools、platform-tools、`platforms;android-37`、与 AGP 匹配的 build-tools、NDK（版本按 AGP 要求，构建时定）、`rustup target add aarch64-linux-android`、cargo-ndk（或直接用 NDK clang + cargo，二选一）。经验（Rust 项目教训）：apt 很慢，优先直接下载官方包；只有 `~` 持久，装了什么版本要记下来。
- 验证（按 android-dev skill 的 loop）：`./gradlew assembleDebug` → `adb install -r` → `adb shell monkey -p <pkg> -c android.intent.category.LAUNCHER 1` → `pidof` / `screencap` / `logcat`。Rust 那套 `cargo test` 对 Android 部分不适用；Kotlin 侧用 `./gradlew test`（JVM 单元测试）+ 真机冒烟。
- 模拟器：VM 里大概率没有可用的模拟器（无 KVM 时 x86 镜像极慢，arm 镜像不可用）。先做到 assemble 成功 + 尽量起模拟器；起不来就如实说，安装与连通留给 Leo 真机验。不要为赶进度跳过验证。

## 8. VM 里验证不了的（留给 Leo 真机验）

1. 真实 VPNGate 节点连通（VM 出口拦截到 vpngate.net 的 TLS，与 Rust 版同款限制）。
2. UDP sendto 在 VM 沙箱里被拦（连 loopback 都不行）——VM 里的模拟器同样受影响。
3. Wi-Fi 代理指向 `127.0.0.1` 是否被 Leo 的手机/OEM 接受；不接受时用 Wi-Fi IP 回退（§3）。
4. 前台 Service 在 Leo 手机上的保活表现（各厂商后台策略不同）、电池优化豁免效果。
5. 侧载安装时的 Play Protect 提示。
6. Leo 手机的 ABI（默认 arm64-v8a；用 `adb shell getprop ro.product.cpu.abi` 核对）。
7. 前置代理两条路在真机上是否通（v2rayNG 本地 SOCKS5 优先）。

## 9. 风险与待定（阶段 2 开工前要逐项消掉）

- AGP 9.4.x / Kotlin 2.4.x / Gradle 9.6+ 是 skill 快照里的最新版，构建时核对是否存在、能否下载；不行就退到当时最新的稳定版。
- **eframe 解耦是阶段 2 的前置任务**（§2；`tray.rs` 在 lib 里，`[dependencies]` 含 eframe/rfd/arboard）。
- rustls 在 Android 上的系统根证书：节点 TLS 是 accept-any，不依赖；API/DoH 的 verified TLS 用已打包的 webpki-roots，不依赖系统证书库——构建时验证一次即可。
- tokio 在 NDK 下的运行（epoll，正常可用；signal 处理注意）；JNI 线程与 tokio runtime 生命周期。
- `foregroundServiceType` 取 `dataSync` 是否恰当，构建时按现行 Android 文档核对（Android 14+ 对类型与权限卡得严）。
- 官方 android/skills 里没有通用开发 skill；如需 AGP 升级或测试搭建指引，阶段 2 再取 `build-system/agp/agp-9-upgrade`、`testing/testing-setup` 作补充。

## 10. 交付步骤

- 阶段 0（本文件）：skill 学习 + 设计——已完成，等通知。
- 阶段 1：等 v3.16 推送信号——已收到（main head `54bf0ad5`，v3.16）。
- 阶段 2：按 §6 分 A/B/C 做；每步 assemble + 安装验证。
- 阶段 3：Leo 建空库 `VpngateSU` 并授权后 push；Release 走浏览器任务（与 Rust 版同款：tag、Latest、三附件、公开页核对）。

## 附：核实依据

- `userspace-vpn-client` skill：`~/workspace/custom-skills/userspace-vpn-client/SKILL.md`（架构与发布流程）。
- `android-dev` skill：`~/workspace/custom-skills/android-dev/SKILL.md`（来源 `Quad4-Software/skills`，提交 `6d4dfc65`，0BSD；SKILL.md + references/adb-and-build.md，原样安装，已验证可检索）。
- 官方 `android/skills` 已评估：无通用开发 skill（README 明言不做），只有窄任务 skill；`system/` 下只有一个 glance-appwidget skill。
- 代码核实（v3.16，`~/workspace/vpngate-rust-client/`）：`Cargo.toml` version 0.3.16；`src/socks5.rs` 的 `http_target`（CONNECT/绝对形式/起源形式）与 `serve_mixed` 签名；`src/net.rs` 的 Windows（SChannel）/非 Windows（rustls）分流；`src/tray.rs` 引用 eframe（lib 依赖）；`src/sysproxy.rs` 的非 Windows/macOS 分支为 no-op；`src/config.rs` 的 `load(Some(path))` / `save(path)` 与 `save_cached_nodes_to(path)`；`src/bin/vpngate-gui.rs` 的 6 列导出（第 6 列 probe_ms）。
- VM 环境核实（2026-11-08）：无 JDK/SDK/adb；Rust 工具链在 `~/.cargo/bin`，已装 target 仅 x86_64-pc-windows-gnu 与 x86_64-unknown-linux-gnu。
