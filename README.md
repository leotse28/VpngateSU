# VpngateSU

Android port of [VPNGATE-LITE](https://github.com/leotse28/VPNGATE-LITE) (based on v3.16).

A userspace tunnel client: local mixed SOCKS5 + HTTP proxy port, front SOCKS5 proxy,
and an MS-SSTP tunnel to VPNGate volunteer nodes. Port-proxy only — no virtual
NIC, no routing-table changes, no system-wide VPN.

- Target: Android 11 and above (minSdk 30, targetSdk 36, compileSdk 37); arm64-v8a only
- Status: Phase A done — first APK builds (debug, 0.1.0). See DESIGN.md for the plan.

## How the phone uses it

VpngateSU starts a local mixed proxy on the phone (default 127.0.0.1:10818). Set
that as the proxy of the Wi-Fi network: the browser and proxy-respecting apps
then go through the tunnel. Only that Wi-Fi network is affected; mobile data
does not go through the proxy; UDP does not go through a Wi-Fi HTTP proxy.

## Build (this VM)

Prerequisites are in TOOLCHAIN.md (JDK 17, Android SDK 37, NDK r28c, Rust +
aarch64-linux-android target, cargo-ndk). Environment:

```sh
export JAVA_HOME=~/jdk17 ANDROID_HOME=~/android-sdk
export ANDROID_NDK_HOME=~/android-sdk/ndk/28.2.13676358
export PATH="$HOME/.cargo/bin:$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"
```

Build the Rust core first, then the app:

```sh
cargo ndk -t arm64-v8a build --release --manifest-path rust/jni/Cargo.toml
cp rust/jni/target/aarch64-linux-android/release/libvpngatesu_jni.so app/src/main/jniLibs/arm64-v8a/
./gradlew assembleDebug
```

APK: `app/build/outputs/apk/debug/app-debug.apk`. The `.so` is rebuilt by
cargo-ndk; `app/src/main/jniLibs/*.so` is a build artifact and is not committed.
`gradle-wrapper.jar` is also omitted from the repo (binary) — fetch it or
install Gradle 9.6.0 to run `./gradlew` on a fresh machine. `gradle.properties`
holds VM-local proxy/truststore paths for this VM's egress proxy — review before
building elsewhere.

## Layout

- `app/` — Kotlin + Compose UI, foreground Service, JNI bridge (`NativeBridge`)
- `rust/` — vendored VPNGATE-LITE v3.16 core (GUI feature OFF) + `rust/jni` cdylib bridge
- `DESIGN.md` — porting plan and honest limits; `TOOLCHAIN.md` — toolchain versions
