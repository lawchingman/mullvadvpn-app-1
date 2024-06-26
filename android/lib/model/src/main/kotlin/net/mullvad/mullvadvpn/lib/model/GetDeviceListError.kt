package net.mullvad.mullvadvpn.lib.model

sealed interface GetDeviceListError {
    data class Unknown(val error: Throwable) : GetDeviceListError
}
