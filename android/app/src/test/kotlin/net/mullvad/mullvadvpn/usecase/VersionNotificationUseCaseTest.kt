package net.mullvad.mullvadvpn.usecase

import app.cash.turbine.test
import io.mockk.MockKAnnotations
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import net.mullvad.mullvadvpn.lib.common.test.TestCoroutineRule
import net.mullvad.mullvadvpn.repository.InAppNotification
import net.mullvad.mullvadvpn.ui.VersionInfo
import net.mullvad.mullvadvpn.ui.serviceconnection.AppVersionInfoRepository
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith

@ExtendWith(TestCoroutineRule::class)
class VersionNotificationUseCaseTest {

    private val mockAppVersionInfoRepository: AppVersionInfoRepository = mockk()

    private val versionInfo =
        MutableStateFlow(
            VersionInfo(currentVersion = "", suggestedUpgradeVersion = null, isSupported = true)
        )
    private lateinit var versionNotificationUseCase: VersionNotificationUseCase

    @BeforeEach
    fun setup() {
        MockKAnnotations.init(this)
        every { mockAppVersionInfoRepository.versionInfo() } returns versionInfo

        versionNotificationUseCase =
            VersionNotificationUseCase(
                appVersionInfoRepository = mockAppVersionInfoRepository,
                isVersionInfoNotificationEnabled = true
            )
    }

    @AfterEach
    fun teardown() {
        unmockkAll()
    }

    @Test
    fun `initial state should be empty`() = runTest {
        // Arrange, Act, Assert
        versionNotificationUseCase.notifications().test { assertTrue { awaitItem().isEmpty() } }
    }

    @Test
    fun `when a new version is available use case should emit UpdateAvailable with new version`() =
        runTest {
            versionNotificationUseCase.notifications().test {
                // Arrange, Act
                val upgradeVersionInfo =
                    VersionInfo(
                        currentVersion = "1.0",
                        suggestedUpgradeVersion = "1.1",
                        isSupported = true
                    )
                awaitItem()
                versionInfo.value = upgradeVersionInfo

                // Assert
                assertEquals(
                    awaitItem(),
                    listOf(InAppNotification.UpdateAvailable(upgradeVersionInfo))
                )
            }
        }

    @Test
    fun `when an unsupported version use case should emit UnsupportedVersion notification`() =
        runTest {
            versionNotificationUseCase.notifications().test {
                // Arrange, Act
                val upgradeVersionInfo =
                    VersionInfo(
                        currentVersion = "1.0",
                        suggestedUpgradeVersion = null,
                        isSupported = false
                    )
                awaitItem()
                versionInfo.value = upgradeVersionInfo

                // Assert
                assertEquals(
                    awaitItem(),
                    listOf(InAppNotification.UnsupportedVersion(upgradeVersionInfo))
                )
            }
        }
}
