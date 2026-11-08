plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "io.github.leotse28.vpngatesu"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.leotse28.vpngatesu"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    // No `kotlin {}` block: AGP 9.4 has Kotlin support built in (the
    // org.jetbrains.kotlin.android plugin is rejected since AGP 9.0)
    // and derives the Kotlin JVM target from compileOptions above.
    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(libs.junit)
}

// This VM resolves localhost to ::1 first; the forked test executor
// must reach the Gradle daemon over IPv4 loopback (127.0.0.1), or its
// resultProcessor stays null and the run dies with an NPE in
// SuiteTestDefinitionProcessor.stop(). Same root cause as the daemon
// dispatch failure (see TOOLCHAIN.md §4); the client side is fixed by
// GRADLE_OPTS, the test worker needs it here.
tasks.withType<Test>().configureEach {
    jvmArgs("-Djava.net.preferIPv4Stack=true")
}
