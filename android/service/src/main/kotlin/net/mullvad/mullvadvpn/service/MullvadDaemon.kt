package net.mullvad.mullvadvpn.service

import android.annotation.SuppressLint
import android.content.Context
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import net.mullvad.mullvadvpn.lib.endpoint.ApiEndpoint
import net.mullvad.mullvadvpn.lib.endpoint.ApiEndpointConfiguration
import net.mullvad.mullvadvpn.service.migration.MigrateSplitTunneling

private const val RELAYS_FILE = "relays.json"

@SuppressLint("SdCardPath")
class MullvadDaemon(
    vpnService: MullvadVpnService,
    apiEndpointConfiguration: ApiEndpointConfiguration,
    migrateSplitTunneling: MigrateSplitTunneling
) {
    // Used by JNI
    @Suppress("ProtectedMemberInFinalClass") protected var daemonInterfaceAddress = 0L

    private val shutdownSignal = Channel<Unit>()

    init {
        System.loadLibrary("mullvad_jni")

        prepareFiles(vpnService)

        migrateSplitTunneling.migrate()

        initialize(
            vpnService = vpnService,
            cacheDirectory = vpnService.cacheDir.absolutePath,
            resourceDirectory = vpnService.filesDir.absolutePath,
            apiEndpoint = apiEndpointConfiguration.apiEndpoint()
        )
    }

    suspend fun shutdown() =
        withContext(Dispatchers.IO) {
            val shutdownSignal = async { shutdownSignal.receive() }
            shutdown(daemonInterfaceAddress)
            shutdownSignal.await()
            deinitialize()
        }

    private fun prepareFiles(context: Context) {
        val shouldOverwriteRelayList =
            lastUpdatedTime(context) > File(context.filesDir, RELAYS_FILE).lastModified()

        FileResourceExtractor(context).apply { extract(RELAYS_FILE, shouldOverwriteRelayList) }
    }

    private fun lastUpdatedTime(context: Context): Long =
        context.packageManager.getPackageInfo(context.packageName, 0).lastUpdateTime

    // Used by JNI
    @Suppress("unused")
    private fun notifyDaemonStopped() {
        runBlocking {
            shutdownSignal.send(Unit)
            shutdownSignal.close()
        }
    }

    private external fun initialize(
        vpnService: MullvadVpnService,
        cacheDirectory: String,
        resourceDirectory: String,
        apiEndpoint: ApiEndpoint?
    )

    private external fun deinitialize()

    private external fun shutdown(daemonInterfaceAddress: Long)
}
