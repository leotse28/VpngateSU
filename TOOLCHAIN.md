# VpngateSU 工具链记录（TOOLCHAIN）

- 记录日期：2026-11-08（SGT）
- 记录人：阶段 2 工人 B（工具链安装）
- 目标：AGP 9.4.x / compileSdk 37 / minSdk 30 / JDK 17 / NDK（cargo-ndk 路线）
- 全部装在 `~` 下面（只有 `~` 持久）。未用 apt。

## 1. 版本与路径总表

| 组件 | 版本 | 路径 |
|---|---|---|
| JDK（Temurin 17） | **17.0.21+9**（`openjdk 17.0.21 2026-10-20`） | `~/jdk17` |
| Android cmdline-tools | **12.0**（`sdkmanager --version` = 12.0；zip `commandlinetools-linux-11076708_latest.zip`） | `~/android-sdk/cmdline-tools/latest` |
| platform-tools | **37.0.1**（adb 1.0.41，`adb --version` = `37.0.1-15733141`） | `~/android-sdk/platform-tools` |
| SDK Platform（API 37） | **android-37.0 rev 2** 与 **android-37.2 rev 2**（见 §2 说明） | `~/android-sdk/platforms/android-37.0`、`~/android-sdk/platforms/android-37.2` |
| build-tools | **36.0.0**（aapt2 2.20；AGP 9.4 默认/最低版本，见 §2） | `~/android-sdk/build-tools/36.0.0` |
| NDK | **28.2.13676358（r28c）**（AGP 9.4 默认版本；clang 19.0.1；`ndk-build` = GNU Make 4.3） | `~/android-sdk/ndk/28.2.13676358` |
| Rust | **1.99.1**（cargo 1.99.1 / rustc 1.99.1，stable） | `~/.cargo/bin`（`PATH` 里默认没有，需自行加上） |
| Rust target | **aarch64-linux-android** 已装（另有 `x86_64-pc-windows-gnu`、`x86_64-unknown-linux-gnu`） | rustup |
| cargo-ndk | **4.1.2**（`cargo ndk --version`） | `~/.cargo/bin/cargo-ndk`（另装了 `cargo-ndk-env`、`cargo-ndk-runner`、`cargo-ndk-test`） |

## 2. 版本选择的依据（AGP 9.4.x，官方兼容表，2026-11-08 核对）

来源：Android Developers《Android Gradle plugin 9.4.0 (September 2026)》兼容表：

- Gradle 9.6.0（最低/默认）、**SDK Build Tools 36.0.0**（最低/默认）、**NDK 默认 28.2.13676358**、**JDK 17**、最高 API 37。
- 因此 build-tools 装 36.0.0（不是 37.0.0），NDK 装 28.2.13676358（不是更新的 29/30）。

### API 37 平台没有 `platforms;android-37` 这个包

- Google 的仓库（`repository2-3.xml`，2026-11-08 实测）里 **不存在** `platforms;android-37`；API 37 以扩展级分包提供：`platforms;android-37.0`（rev 2）、`android-37.1`（rev 1）、`android-37.2`（rev 2）。`sdkmanager --list` 证实同样结果。
- 所以任务书里的 `platforms;android-37` 装不上（sdkmanager 只报 `Failed to find package 'platforms;android-37'`，exit 1）——这是包名本身不存在，不是网络问题。
- 本机装了 **37.0 与 37.2 两个**（37.1 未装，需要时 `sdkmanager "platforms;android-37.1"` 即可）。阶段 2 构建时需确认 AGP 9.4 对 `compileSdk 37` 实际解析到哪一个（社区先例：有项目装 37.0，有项目以 37.2 编译；Gradle 也可能自动下载所需平台）。

## 3. 环境变量（阶段 2 构建时用这些值）

```sh
export JAVA_HOME=$HOME/jdk17
export ANDROID_HOME=$HOME/android-sdk
export ANDROID_NDK_HOME=$HOME/android-sdk/ndk/28.2.13676358
export PATH=$HOME/jdk17/bin:$HOME/.cargo/bin:$HOME/android-sdk/platform-tools:$PATH
```

注意：`PATH` 默认不含 `~/.cargo/bin` 与 `~/jdk17/bin`，每次新 shell 都要加上（或写进 `~/.profile`，本次未改 shell 启动文件）。

## 4. sdkmanager 必须这样调才通（本机出口代理的三个坑）

直接跑 `sdkmanager` 会失败，原因是 VM 出口走代理 `hatch-egress-proxy:3128`，而 sdkmanager/Java 各有各的毛病。以下命令是**实测通过**的完整形态（许可证用 `yes |` 喂）：

```sh
export JAVA_HOME=$HOME/jdk17 ANDROID_HOME=$HOME/android-sdk
export JDK_JAVA_OPTIONS="-Djava.net.preferIPv4Stack=true -Djava.io.tmpdir=$HOME/.tmp-java -Djavax.net.ssl.trustStore=$HOME/tmp-java/egress-truststore.jks -Djavax.net.ssl.trustStorePassword=changeit"
yes | env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY \
  $HOME/android-sdk/cmdline-tools/latest/bin/sdkmanager \
  --proxy=http --proxy_host=hatch-egress-proxy --proxy_port=3128 \
  "platform-tools" "platforms;android-37.0" "platforms;android-37.2" "build-tools;36.0.0" "ndk;28.2.13676358"
```

三个坑（都已实测定位，勿重蹈）：

1. **sdkmanager 不认 JVM 的 `-Dhttps.proxyHost`。** 它拉仓库清单时用 `proxy: DIRECT`（FINEST 日志证实），直连失败（`curl --noproxy` 得 000）。必须用它自己的 `--proxy=http --proxy_host=hatch-egress-proxy --proxy_port=3128` 参数。无认证即可通（`curl -x http://hatch-egress-proxy:3128` 无账号密码也返回 200）。
2. **Java 默认走 IPv6 时 CONNECT 解析崩掉。** `hatch-egress-proxy` 在 `/etc/hosts` 里同时有 IPv6 与 IPv4；Java 默认优先 IPv6，`HttpURLConnection.doTunneling0` 报 `NoSuchElementException`（`StringTokenizer.nextToken`，JDK 17.0.21 源码 2277 行即解析 CONNECT 状态行处），而代理返回的 `HTTP/1.1 200 Connection Established` 本身是正常的。加 `-Djava.net.preferIPv4Stack=true` 后立即通（最小 Java 程序实测 200）。
3. **出口代理 MITM 证书会轮换，Java 信任库会过期。** 代理对 TLS 做中间人，出示由 `CN = Hatch Sandbox Egress CA, O = Hatch` 签发的证书；Java 默认 cacerts 不认它。做法：复制 JDK 的 cacerts，加进当前 `/run/hatch/egress-tls/hatch-egress-ca.pem`，存为 `~/tmp-java/egress-truststore.jks`，用 `-Djavax.net.ssl.trustStore=… -Djavax.net.ssl.trustStorePassword=changeit` 指定。**2026-11-08 当天该 CA 至少轮换过一次**（07:10 导入的指纹 `3A:15:…`，07:25 左右 live 文件已是 `A3:02:99:83:…`；旧库随即报 `PKIX path validation failed: signature check failed`，sdkmanager 表现为 `IO exception while downloading manifest`）。**每次跑 sdkmanager 前先重建一次信任库**（复制 cacerts + 导入当前 pem，见 §5 命令）；若将来某天 sdkmanager 又报 `Failed to download any source lists!`，先检查 CA 指纹是否又变了。
   - 附：`env -u http_proxy …` 是为了去掉环境变量里带账号密码的代理 URL（`http://hatch-runtime:…@hatch-egress-proxy:3128`）；留着它时 Java 也会失败。代理密码不要写进任何文件。

### 另两个坑（与上面无关，但同样致命）

- **`/tmp` 只有 512 MB 且会满。** 本次下载的两个包（185 MB + 147 MB）一度把 `/tmp` 撑到 100%，导致 `cargo install cargo-ndk` 以 `No space left on device` 失败、sdkmanager 报 JVM 共享内存不足警告。已把下载物移到 `~/toolchain-dl/`；`cargo install` 时用 `TMPDIR=$HOME/tmp-cargo CARGO_TARGET_DIR=$HOME/cargo-install-target`；Java 用 `-Djava.io.tmpdir=$HOME/.tmp-java`。**不要再把大文件放 `/tmp`**。
- **不要用 apt。** JDK 与 cmdline-tools 均为官方直链下载（curl，一次成功，无需重试）：
  - JDK：`https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse` → 解到 `~/jdk17`（`--strip-components=1`）
  - cmdline-tools：`https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip` → 解到 `~/android-sdk/cmdline-tools/latest`

## 5. 重建信任库的命令（跑 sdkmanager 之前先跑）

```sh
export JAVA_HOME=$HOME/jdk17
rm -f ~/tmp-java/egress-truststore.jks
cp $JAVA_HOME/lib/security/cacerts ~/tmp-java/egress-truststore.jks
$JAVA_HOME/bin/keytool -importcert -noprompt -trustcacerts -alias hatch-egress-ca \
  -file /run/hatch/egress-tls/hatch-egress-ca.pem \
  -keystore ~/tmp-java/egress-truststore.jks -storepass changeit
# 核对指纹与 live 文件一致：
$JAVA_HOME/bin/keytool -list -keystore ~/tmp-java/egress-truststore.jks -storepass changeit -alias hatch-egress-ca | grep -i sha-256
openssl x509 -in /run/hatch/egress-tls/hatch-egress-ca.pem -noout -fingerprint -sha256
```

## 6. 验证记录（2026-11-08，全部通过）

```
$ sdkmanager --list_installed
  build-tools;36.0.0     | 36.0.0        | Android SDK Build-Tools 36
  ndk;28.2.13676358      | 28.2.13676358 | NDK (Side by side) 28.2.13676358
  platform-tools         | 37.0.1        | Android SDK Platform-Tools
  platforms;android-37.0 | 2             | Android SDK Platform 37.0
  platforms;android-37.2 | 2             | Android SDK Platform 37.2

$ ~/android-sdk/platform-tools/adb --version
  Android Debug Bridge version 1.0.41 / Version 37.0.1-15733141

$ ~/android-sdk/build-tools/36.0.0/aapt2 version
  Android Asset Packaging Tool (aapt) 2.20-13193326

$ ~/android-sdk/ndk/28.2.13676358/ndk-build --version
  GNU Make 4.3（另：clang 19.0.1；aarch64-linux-android21-clang 存在）

$ ~/jdk17/bin/java -version
  openjdk version "17.0.21" 2026-10-20 / OpenJDK Runtime Environment Temurin-17.0.21+9

$ rustup target list --installed
  aarch64-linux-android / x86_64-pc-windows-gnu / x86_64-unknown-linux-gnu
$ cargo ndk --version
  cargo-ndk 4.1.2
```

交叉编译冒烟测试（`~/toolchain-dl/ndk-smoke/ndkhello`，空 lib crate）：

```
$ cargo ndk -t arm64-v8a build --release
  Building arm64-v8a (aarch64-linux-android)
  Compiling ndkhello v0.1.0
  Finished `release` profile [optimized] target(s) in 0.61s
  → target/aarch64-linux-android/release/libndkhello.rlib 已生成
```

（注：空 lib crate 只产 `.rlib`，没有 `.so` 是正常的；能编过即证明 NDK clang + target + cargo-ndk 链路通。）

## 7. 走 cargo-ndk 还是 NDK clang 直配？

**选了 cargo-ndk。** `cargo install cargo-ndk` 一次装上（4.1.2），冒烟测试一次通过。没走“NDK clang 直接给 cargo 配链接器”的备用路线，因此也不需要写 `.cargo/config.toml` 的 linker 配置。若将来 cargo-ndk 出问题，备用方案是：`~/.cargo/config.toml` 里给 `aarch64-linux-android` 配 `linker = "<ndk>/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"`，`ar = "…/llvm-ar"`。

## 8. 下次 VM 替换后：哪些要重装、哪些还在

- **都在 `~` 下，理论上都在**：JDK（`~/jdk17`）、SDK（`~/android-sdk`）、信任库（`~/tmp-java/egress-truststore.jks`）、Rust 工具链（`~/.cargo`、`~/.rustup`）、cargo-ndk、下载原包（`~/toolchain-dl/temurin17.tar.gz`、`cmdline-tools.zip`）与安装日志（`~/toolchain-dl/*.log`）——VM 替换后应直接可用，**不需要重装**。
- **仍需做的事**：① 新 shell 里重设 §3 的环境变量（`PATH` 不含 `~/.cargo/bin` 与 `~/jdk17/bin` 是常态）；② 跑 sdkmanager 前按 §5 **重建一次信任库**（CA 可能已轮换）；③ 若 `/tmp` 又被占满，`cargo install` 与 Java 仍按 §4 用 `~/tmp-java`、`~/tmp-cargo`。
- **若 `~` 之外真丢了东西**（按理不会）：重装顺序是 JDK → cmdline-tools → sdkmanager 装 5 个包 → `rustup target add aarch64-linux-android` → `cargo install cargo-ndk`；安装脚本在 `~/toolchain-dl/install-sdk.sh`（内含 sdkmanager 完整参数，许可证用 `yes |`）。
- 磁盘占用：`~/android-sdk` 2.8 GB、`~/jdk17` 319 MB；替换后剩余空间 130 GB，充足。

## 9. 未装上的东西

无。任务书 5 项全部装上并验证通过。唯一偏离任务书的是：`platforms;android-37` 这个包名在 Google 仓库里不存在，改装了 `android-37.0` 与 `android-37.2`（见 §2）。

## 10. Gradle 构建必须这样调才通（2026-11-08 补，Phase A 构建实测）

根因：本机 `localhost` 先解析到 `::1`，而 Gradle 守护进程与测试 worker 都监听/连接 `127.0.0.1`。三条规则，缺一不可：

1. **不要用 `./gradlew`。** wrapper JVM 不读项目的 truststore/proxy 配置，下载 Gradle dist 时 TLS 断在代理上（`Broken pipe`）。改用已装好的 `~/gradle-9.6.0/bin/gradle`（dist 已缓存在 `~/.gradle/wrapper/dists/gradle-9.6.0-bin/`）。`gradle/wrapper/gradle-wrapper.jar`（48 KB 二进制）也因此**不进仓库**——新机器须自行取 jar 或装 Gradle 9.6.0（见 README）。
2. **必须设 `GRADLE_USER_HOME=/home/hatch/.gradle`。** shell 以 root 身份跑时 Java 的 `user.home=/root`，Gradle 默认用 `/root/.gradle`（空注册表 + 未下完的 dist），而缓存与守护进程注册表都在 `/home/hatch/.gradle`。不设它，守护进程每次都起新实例然后报 `Could not dispatch a message to the daemon`。
3. **客户端与测试 worker 都要 `-Djava.net.preferIPv4Stack=true`。** 客户端：`GRADLE_OPTS="-Djava.net.preferIPv4Stack=true"`（`gradle.properties` 里的 `org.gradle.jvmargs` 只管守护进程，不管启动客户端的 JVM）。测试 worker：`app/build.gradle.kts` 末尾已加 `tasks.withType<Test>().configureEach { jvmArgs("-Djava.net.preferIPv4Stack=true") }`——不加它，`:app:testDebugUnitTest` 死在 `SuiteTestDefinitionProcessor.stop()` 的 NPE（`resultProcessor` 为 null，fork 出的 executor 连不上守护进程）。

实测通过的完整命令（2026-11-08 08:18 UTC，BUILD SUCCESSFUL，22s）：

```sh
cd ~/workspace/VpngateSU
export JAVA_HOME=~/jdk17 ANDROID_HOME=~/android-sdk ANDROID_NDK_HOME=~/android-sdk/ndk/28.2.13676358
export GRADLE_USER_HOME=/home/hatch/.gradle GRADLE_OPTS="-Djava.net.preferIPv4Stack=true"
export PATH="$HOME/.cargo/bin:$HOME/jdk17/bin:$HOME/android-sdk/platform-tools:$PATH"
~/gradle-9.6.0/bin/gradle test assembleDebug
```

另外：`~/.gradle/gradle.properties`（用户级，不进仓库）已配代理 + truststore + `org.gradle.java.home`；项目内 `gradle.properties` 含本机 truststore/tmpdir 路径，仅作构建环境说明，随代码入库。
