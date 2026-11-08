// Top-level build file: plugin versions live in gradle/libs.versions.toml.
// NOTE (AGP 9.4): there is deliberately NO org.jetbrains.kotlin.android
// plugin — AGP 9.0+ has Kotlin support built in and rejects it.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}
