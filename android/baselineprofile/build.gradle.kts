import org.gradle.configurationcache.extensions.capitalized

plugins {
    id(Dependencies.Plugin.androidTestId)
    id(Dependencies.Plugin.baselineProfileId)
    id(Dependencies.Plugin.kotlinAndroidId)
}

android {
    namespace = "net.mullvad.mullvadvpn.baselineprofile"
    compileSdk = Versions.Android.compileSdkVersion

    defaultConfig {
        minSdk = Versions.Android.minSdkVersion
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        testInstrumentationRunnerArguments["androidx.benchmark.suppressErrors"] = "EMULATOR,DEBUGGABLE"
        //testInstrumentationRunnerArguments["targetAppId"] = "net.mullvad.mullvadvpn"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = true
    }

    kotlinOptions {
        jvmTarget = Versions.jvmTarget
    }

    targetProjectPath = ":app"

    lint {
        lintConfig = file("${rootProject.projectDir}/config/lint.xml")
        abortOnError = true
        warningsAsErrors = true
    }

    packaging {
        resources {
            pickFirsts += setOf(
                // Fixes packaging error caused by: jetified-junit-*
                "META-INF/LICENSE.md",
                "META-INF/LICENSE-notice.md"
            )
        }
    }

    //flavorDimensions += listOf("billing", "infrastructure")
    /*productFlavors {
        create("oss") { dimension = "billing" }
        create("play") { dimension = "billing" }
        create("prod") { dimension = "infrastructure" }
        create("devmole") { dimension = "infrastructure" }
        create("stagemole") { dimension = "infrastructure" }
    }*/
    /*flavorDimensions += FlavorDimensions.BILLING
    flavorDimensions += FlavorDimensions.INFRASTRUCTURE
    productFlavors {
        create(Flavors.OSS) { dimension = FlavorDimensions.BILLING }
        create(Flavors.PROD) {
            dimension = FlavorDimensions.INFRASTRUCTURE
        }
    }*/
    flavorDimensions += listOf("billing", "infrastructure")
    productFlavors {
        create(Flavors.OSS) { dimension = FlavorDimensions.BILLING }
        create(Flavors.PROD) { dimension = FlavorDimensions.INFRASTRUCTURE }
    }
}

// This is the configuration block for the Baseline Profile plugin.
// You can specify to run the generators on a managed devices or connected devices.
baselineProfile {
    useConnectedDevices = true
}

dependencies {
    implementation("androidx.test.ext:junit:1.1.5")
    implementation("androidx.test.espresso:espresso-core:3.5.1")
    implementation("androidx.test.uiautomator:uiautomator:2.3.0")
    implementation("androidx.benchmark:benchmark-macro-junit4:1.2.4")
}

androidComponents {
    beforeVariants { variantBuilder ->
        variantBuilder.enable =
            variantBuilder.let { currentVariant ->
                val enabledVariants =
                    enabledBaselineVariantTriples.map { (billing, infra, buildType) ->
                        billing + infra.capitalized() + buildType.capitalized()
                    }
                System.out.println(currentVariant.name)
                //(currentVariant.name == "ossProdBenchmarkRelease") or (currentVariant.name == "ossProdDebug")
                //currentVariant.buildType == "benchmark"
                true
            }
    }
    /*onVariants { v ->
        val artifactsLoader = v.artifacts.getBuiltArtifactsLoader()
        v.instrumentationRunnerArguments.put(
            "targetAppId",
            v.testedApks.map { artifactsLoader.load(it)?.applicationId }
        )
    }*/
}
