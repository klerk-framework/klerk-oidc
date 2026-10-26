import org.gradle.kotlin.dsl.invoke
import org.jetbrains.dokka.gradle.formats.DokkaFormatPlugin
import org.jetbrains.dokka.gradle.internal.InternalDokkaGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.ExplicitApiMode

plugins {
    kotlin("jvm") version "2.4.10"
    kotlin("plugin.serialization") version "2.4.10"
    `java-library`
    `maven-publish`
    id("org.jetbrains.dokka") version "2.2.0"
    id("org.jlleitschuh.gradle.ktlint") version "14.2.0"
}

val klerkVersion = "1.0.0-beta.7-SNAPSHOT"
val klerkWebVersion = "1.0.0-alpha.2-SNAPSHOT"
val klerkWebExtraVersion = "1.0.0-alpha.1-SNAPSHOT"
val nimbusVersion = "11.38.2"
val ktorVersion = "3.5.0" // Keep in sync with ktor-bom in klerk-bom.
val kotlinLoggingVersion = "2.1.21"
val slf4jVersion = "2.0.3"

group = "dev.klerkframework"
version = "1.0.0-alpha.1-SNAPSHOT"

dependencies {
    api("dev.klerkframework:klerk:$klerkVersion")
    api("dev.klerkframework:klerk-web:$klerkWebVersion")
    api("dev.klerkframework:klerk-web-extra:$klerkWebExtraVersion")
    implementation("com.nimbusds:oauth2-oidc-sdk:$nimbusVersion")
    implementation("io.ktor:ktor-server-html-builder:$ktorVersion")
    implementation("io.ktor:ktor-server-core-jvm:$ktorVersion")
    implementation("io.github.microutils:kotlin-logging-jvm:$kotlinLoggingVersion")
    testImplementation(kotlin("test"))
    testImplementation("org.slf4j:slf4j-simple:$slf4jVersion")
    testImplementation("io.ktor:ktor-server-test-host:$ktorVersion")
    testImplementation("io.ktor:ktor-server-netty-jvm:$ktorVersion")
    testImplementation("io.ktor:ktor-client-core:$ktorVersion")
}

publishing {
    publications {
        create<MavenPublication>("Maven") {
            artifactId = "klerk-oidc"
            from(components["java"])
        }
    }
}

java {
    withSourcesJar()
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
    explicitApi = ExplicitApiMode.Strict
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions.optIn.add("dev.klerkframework.klerk.ExperimentalKlerkApi")
}

// Declares Markdown Gradle plugin
@OptIn(InternalDokkaGradlePluginApi::class)
abstract class DokkaMarkdownPlugin : DokkaFormatPlugin(formatName = "markdown") {
    override fun DokkaFormatPlugin.DokkaFormatPluginContext.configure() {
        project.dependencies {
            // Sets up current project generation
            dokkaPlugin(dokka("gfm-plugin"))

            // Sets up multi-project generation
            formatDependencies.dokkaPublicationPluginClasspathApiOnly.dependencies.addLater(
                dokka("gfm-template-processing-plugin"),
            )
        }
    }
}
// Applies the plugin
apply<DokkaMarkdownPlugin>()
