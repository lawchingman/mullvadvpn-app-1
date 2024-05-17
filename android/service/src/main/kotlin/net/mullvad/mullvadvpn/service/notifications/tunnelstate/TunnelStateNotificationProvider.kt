package net.mullvad.mullvadvpn.service.notifications.tunnelstate

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onStart
import kotlinx.coroutines.flow.stateIn
import net.mullvad.mullvadvpn.lib.shared.AccountRepository
import net.mullvad.mullvadvpn.lib.shared.ConnectionProxy
import net.mullvad.mullvadvpn.lib.shared.VpnPermissionRepository
import net.mullvad.mullvadvpn.model.ActionAfterDisconnect
import net.mullvad.mullvadvpn.model.ChannelId
import net.mullvad.mullvadvpn.model.DeviceState
import net.mullvad.mullvadvpn.model.ErrorStateCause
import net.mullvad.mullvadvpn.model.Notification
import net.mullvad.mullvadvpn.model.NotificationAction
import net.mullvad.mullvadvpn.model.NotificationId
import net.mullvad.mullvadvpn.model.NotificationTunnelState
import net.mullvad.mullvadvpn.model.NotificationUpdate
import net.mullvad.mullvadvpn.model.TunnelState
import net.mullvad.mullvadvpn.service.notifications.NotificationProvider

class TunnelStateNotificationProvider(
    connectionProxy: ConnectionProxy,
    vpnPermissionRepository: VpnPermissionRepository,
    accountRepository: AccountRepository,
    channelId: ChannelId,
    scope: CoroutineScope
) : NotificationProvider<Notification.Tunnel> {
    internal val notificationId = NotificationId(2)

    override val notifications: StateFlow<NotificationUpdate<Notification.Tunnel>> =
        combine(
                connectionProxy.tunnelState,
                connectionProxy.tunnelState.actionAfterDisconnect().distinctUntilChanged(),
                accountRepository.accountState
            ) {
                tunnelState: TunnelState,
                actionAfterDisconnect: ActionAfterDisconnect?,
                accountState ->
                if (accountState is DeviceState.LoggedOut) {
                    return@combine NotificationUpdate.Cancel(notificationId)
                }
                val notificationTunnelState =
                    tunnelState(
                        tunnelState,
                        actionAfterDisconnect,
                        vpnPermissionRepository.hasVpnPermission(),
                        vpnPermissionRepository.getAlwaysOnVpnAppName()
                    )

                return@combine NotificationUpdate.Notify(
                    notificationId,
                    Notification.Tunnel(
                        channelId = channelId,
                        state = notificationTunnelState,
                        actions = listOfNotNull(notificationTunnelState.toAction()),
                        ongoing = notificationTunnelState is NotificationTunnelState.Connected
                    )
                )
            }
            .stateIn(scope, SharingStarted.Eagerly, NotificationUpdate.Cancel(notificationId))

    private fun tunnelState(
        tunnelState: TunnelState,
        actionAfterDisconnect: ActionAfterDisconnect?,
        hasVpnPermission: Boolean,
        alwaysOnVpnPermissionName: String?
    ): NotificationTunnelState =
        tunnelState.toNotificationTunnelState(
            actionAfterDisconnect,
            hasVpnPermission,
            alwaysOnVpnPermissionName
        )

    private fun Flow<TunnelState>.actionAfterDisconnect(): Flow<ActionAfterDisconnect?> =
        filterIsInstance<TunnelState.Disconnecting>()
            .map<TunnelState.Disconnecting, ActionAfterDisconnect?> { it.actionAfterDisconnect }
            .onStart { emit(null) }

    private fun TunnelState.toNotificationTunnelState(
        actionAfterDisconnect: ActionAfterDisconnect?,
        hasVpnPermission: Boolean,
        alwaysOnVpnPermissionName: String?
    ) =
        when (this) {
            is TunnelState.Disconnected -> NotificationTunnelState.Disconnected(hasVpnPermission)
            is TunnelState.Connecting -> {
                if (actionAfterDisconnect == ActionAfterDisconnect.Reconnect) {
                    NotificationTunnelState.Reconnecting
                } else {
                    NotificationTunnelState.Connecting
                }
            }
            is TunnelState.Disconnecting -> {
                if (actionAfterDisconnect == ActionAfterDisconnect.Reconnect) {
                    NotificationTunnelState.Reconnecting
                } else {
                    NotificationTunnelState.Disconnecting
                }
            }
            is TunnelState.Connected -> NotificationTunnelState.Connected
            is TunnelState.Error -> toNotificationTunnelState(alwaysOnVpnPermissionName)
        }

    private fun TunnelState.Error.toNotificationTunnelState(
        alwaysOnVpnPermissionName: String?
    ): NotificationTunnelState.Error {
        val cause = errorState.cause
        return when {
            cause is ErrorStateCause.IsOffline -> NotificationTunnelState.Error.DeviceOffline
            cause is ErrorStateCause.InvalidDnsServers -> NotificationTunnelState.Error.Blocking
            cause is ErrorStateCause.VpnPermissionDenied ->
                alwaysOnVpnPermissionName?.let { NotificationTunnelState.Error.AlwaysOnVpn }
                    ?: NotificationTunnelState.Error.VpnPermissionDenied
            errorState.isBlocking -> NotificationTunnelState.Error.Blocking
            else -> NotificationTunnelState.Error.Critical
        }
    }

    private fun NotificationTunnelState.toAction(): NotificationAction.Tunnel =
        when (this) {
            is NotificationTunnelState.Disconnected -> {
                if (this.hasVpnPermission) {
                    NotificationAction.Tunnel.Connect
                } else {
                    NotificationAction.Tunnel.RequestPermission
                }
            }
            NotificationTunnelState.Disconnecting -> NotificationAction.Tunnel.Connect
            NotificationTunnelState.Connected,
            NotificationTunnelState.Error.Blocking -> NotificationAction.Tunnel.Disconnect
            NotificationTunnelState.Connecting -> NotificationAction.Tunnel.Cancel
            NotificationTunnelState.Reconnecting -> NotificationAction.Tunnel.Cancel
            is NotificationTunnelState.Error.Critical,
            NotificationTunnelState.Error.DeviceOffline,
            NotificationTunnelState.Error.VpnPermissionDenied,
            NotificationTunnelState.Error.AlwaysOnVpn -> NotificationAction.Tunnel.Dismiss
        }
}
