package net.mullvad.mullvadvpn.model

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
enum class TransportProtocol : Parcelable {
    Tcp,
    Udp
}