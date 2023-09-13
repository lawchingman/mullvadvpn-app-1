//
//  AbstractTun.swift
//  PacketTunnel
//
//  Created by Emils on 17/03/2023.
//  Copyright © 2023 Mullvad VPN AB. All rights reserved.
//

import CoreFoundation
import Foundation
import WireGuardKitTypes
import Network
import NetworkExtension
import WireGuardKit
import WireGuardKitTypes
import WireGuardKitC

// Wrapper class around AbstractTun to provide an interface similar to WireGuardAdapter.
class AbstractTunAdapter {
    private let abstractTun: AbstractTun
    private let queue: DispatchQueue
    init(queue: DispatchQueue, packetTunnel: PacketTunnelProvider, logClosure: @escaping (String) -> Void) {

        self.queue = queue
        abstractTun = AbstractTun(queue: queue, packetTunnel: packetTunnel, logClosure: logClosure)
    }

    public func start(tunnelConfiguration: PacketTunnelConfiguration) -> Result<(), AbstractTunError> {
        return abstractTun.start(tunnelConfig: tunnelConfiguration)
    }

    public func block(tunnelConfiguration: TunnelConfiguration) -> Result<(), AbstractTunError> {
        return abstractTun.block(tunnelConfiguration: tunnelConfiguration)
    }

    public func update(tunnelConfiguration: PacketTunnelConfiguration) -> Result<(), AbstractTunError> {
        return abstractTun.update(tunnelConfiguration: tunnelConfiguration)
    }

    public func stop(completionHandler: @escaping (WireGuardAdapterError?) -> Void)  {
        abstractTun.stopOnQueue()
        completionHandler(nil)
    }

    public func stats() -> WgStats {
        return abstractTun.stats
    }

    /// Returns the tunnel device interface name, or nil on error.
    /// - Returns: String.
    public var interfaceName: String? {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else { return nil }

        var buffer = [UInt8](repeating: 0, count: Int(IFNAMSIZ))

        return buffer.withUnsafeMutableBufferPointer { mutableBufferPointer in
            guard let baseAddress = mutableBufferPointer.baseAddress else { return nil }

            var ifnameSize = socklen_t(IFNAMSIZ)
            let result = getsockopt(
                tunnelFileDescriptor,
                2 /* SYSPROTO_CONTROL */,
                2 /* UTUN_OPT_IFNAME */,
                baseAddress,
                &ifnameSize)

            if result == 0 {
                return String(cString: baseAddress)
            } else {
                return nil
            }
        }
    }

    /// Tunnel device file descriptor.
    private var tunnelFileDescriptor: Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                return fd
            }
        }
        return nil
    }




}

class AbstractTun: NSObject {
    private var tunRef: OpaquePointer?
    private var dispatchQueue: DispatchQueue

    private let packetTunnelProvider: PacketTunnelProvider

    private var v4SessionMap: [UInt32: NWUDPSession] = [UInt32: NWUDPSession]()
    private var v6SessionMap: [[UInt16]: NWUDPSession] = [[UInt16]: NWUDPSession]()

    private let tunQueue = DispatchQueue(label: "AbstractTun", qos: .userInitiated)

    private var wgTaskTimer: DispatchSourceTimer?
    private let logClosure: (String) -> Void

    private var socketObservers: [UInt32: NSKeyValueObservation] = [:]

    private (set) var bytesReceived: UInt64 = 0
    private (set) var bytesSent: UInt64 = 0
    
    var stats: WgStats {
        get {
            return WgStats(bytesReceived: bytesReceived, bytesSent: bytesSent)
        }
    }

    init(queue: DispatchQueue, packetTunnel: PacketTunnelProvider, logClosure: @escaping (String) -> Void) {
        dispatchQueue = queue;
        packetTunnelProvider = packetTunnel
        self.logClosure = logClosure
    }



    deinit {
         self.stop()
    }

    func stopAbstractTun() {
        abstract_tun_drop(self.tunRef)
        self.tunRef = nil
    }

    func stopOnQueue() {
        dispatchQueue.sync {
            [weak self] in
            self?.stop()
        }
    }
    func stop() {
        wgTaskTimer?.cancel()
        wgTaskTimer = nil
        stopAbstractTun()
    }

    func update(tunnelConfiguration: PacketTunnelConfiguration) -> Result<(), AbstractTunError> {
        dispatchPrecondition(condition: .onQueue(dispatchQueue))
        stop()
        bytesSent = 0
        bytesReceived = 0
        return start(tunnelConfig: tunnelConfiguration)
    }

    func start(tunnelConfig: PacketTunnelConfiguration) -> Result<(), AbstractTunError> {
        dispatchPrecondition(condition: .onQueue(dispatchQueue))

        wgTaskTimer = DispatchSource.makeTimerSource(queue: dispatchQueue)
        wgTaskTimer?.setEventHandler(handler: {
            [weak self] in
            guard let self = self else { return }
            self.handleTimerEvent()
        })
        wgTaskTimer?.schedule(deadline: .now() + .milliseconds(10), repeating: .milliseconds(100))

        let singlePeer = tunnelConfig.wgTunnelConfig.peers[0];

        let privateKey = tunnelConfig.wgTunnelConfig.interface.privateKey.rawValue;
        guard let peerEndpoint = singlePeer.endpoint else {
            return .failure(AbstractTunError.noPeers)
        }
        let peerAddr = peerEndpoint.host


        var addrBytes = Data(count: 16)
        var addressKind = UInt8(2)
        switch peerAddr {
        case .ipv4(let addr) :
            addrBytes[0...3] = addr.rawValue[0...3]
            addressKind = UInt8(AF_INET)
        case .ipv6(let addr) :
            addrBytes[0...16] = addr.rawValue[0...16]
            addressKind = UInt8(AF_INET6)
        default :
            break;
        };


        var params = IOSTunParams()
        params.peer_addr_version = addressKind
        params.peer_port = singlePeer.endpoint?.port.rawValue ?? UInt16(0)

        withUnsafeMutableBytes(of: &params.peer_key) {
            let _ = singlePeer.publicKey.rawValue.copyBytes(to:$0)
        }

        withUnsafeMutableBytes(of: &params.private_key) {
            let _ = privateKey.copyBytes(to: $0)
        }

        withUnsafeMutableBytes(of: &params.peer_addr_bytes) {
            let _ = addrBytes.copyBytes(to: $0)
        }

        withUnsafePointer(to: params) {
            tunRef = abstract_tun_init_instance($0)
        }
        if tunRef == nil {
            return .failure(AbstractTunError.initializationError)
        }
        packetTunnelProvider.packetFlow.readPackets(completionHandler: { [weak self] (data, ipv) in
            self?.readPacketTunnelBytes(data, ipversion: ipv)
        })

        self.initializeV4Sockets(peerConfigurations: tunnelConfig.wgTunnelConfig.peers)

        wgTaskTimer?.resume()

        return setConfiguration(tunnelConfig.wgTunnelConfig)
    }

    func setConfiguration(_ config: TunnelConfiguration) -> Result<(), AbstractTunError> {
        let dispatchGroup = DispatchGroup()
        dispatchGroup.enter()
        var systemError: Error?

        self.packetTunnelProvider.setTunnelNetworkSettings(generateNetworkSettings(tunnelConfiguration: config)) { error in
            systemError = error
            dispatchGroup.leave()
        }

        let setNetworkSettingsTimeout: Int = 5
        switch dispatchGroup.wait(wallTimeout: .now() + .seconds(setNetworkSettingsTimeout)) {
        case .success:
            if let error = systemError {
                return .failure(AbstractTunError.setNetworkSettings(error))
            }
            return .success(())
        case .timedOut:
            return .failure(AbstractTunError.setNetworkSettingsTimeout)

        }
    }

    func readPacketTunnelBytes(_ traffic: [Data], ipversion: [NSNumber]) {
        guard let tunPtr = self.tunRef else {
            return
        }
        traffic.forEach { packet in
            receiveHostTraffic(tunPtr: tunPtr, packet)
        }
        packetTunnelProvider.packetFlow.readPackets(completionHandler: self.readPacketTunnelBytes)
    }

    func receiveTunnelTraffic(_ traffic: [Data]) {
        guard let tunPtr = self.tunRef else {
            return
        }

        
        var input_ptr = UnsafeMutablePointer<SwiftDataArray>.allocate(capacity: 1)
        input_ptr.initialize(to: DataArray(data: traffic).toRaw())
        let output_v4 = UnsafeMutablePointer<SwiftDataArray>.allocate(capacity: 1)
        let output_v6 = UnsafeMutablePointer<SwiftDataArray>.allocate(capacity: 1)
        
        abstract_tun_handle_tunnel_traffic(tunPtr, input_ptr, output_v4, output_v6)
        
         let totalDataReceived = traffic.reduce(into: UInt64(0)) {result, current in
            result += UInt64(current.count)
        }
        self.bytesReceived += totalDataReceived       
        traffic.forEach { data in
            let rawData = (data as NSData).bytes
        }
        
        // TODO: handle UDP writes from output
    }

    func receiveHostTraffic(tunPtr: OpaquePointer, _ data: Data) {
        guard let tunPtr = self.tunRef else {
            return
        }
        
        let rawData = (data as NSData).bytes
        // abstract_tun_handle_host_traffic(tunPtr, rawData, UInt(data.count))
    }

    func handleTimerEvent() {
        guard let tunPtr = self.tunRef else {
            return
        }
        
        let output_v4 = UnsafeMutablePointer<SwiftDataArray>.allocate(capacity: 1)
        let output_v6 = UnsafeMutablePointer<SwiftDataArray>.allocate(capacity: 1)
        
        abstract_tun_handle_timer_event(tunPtr, output_v4, output_v6)
    }

    private static func handleUdpSendV4(
        ctx: UnsafeRawPointer?,
        addr: UInt32,
        port: UInt16,
        buffer: UnsafePointer<UInt8>?,
        size: UInt
    ) {
        guard let ctx = ctx else { return }
        guard let buffer = buffer else { return }

        let unmanagedInstance = Unmanaged<AbstractTun>.fromOpaque(ctx)
        let abstractTun = unmanagedInstance.takeUnretainedValue()
        let packetBytes = Data(bytes: buffer, count: Int(size))

        var socket: NWUDPSession;
        let dispatchGroup = DispatchGroup()
        if let existingSocket = abstractTun.v4SessionMap[addr] {
            socket = existingSocket
            
            if socket.state == .ready {
                dispatchGroup.enter()
                socket.writeDatagram(packetBytes) { error in
                    if let error = error {
                        print(error)
                    }
                    dispatchGroup.leave()
                }
                dispatchGroup.wait()
                abstractTun.bytesSent += UInt64(size)
            }
        }
    }

    private func initializeV4Sockets(peerConfigurations peers: [PeerConfiguration]) {
        var map = [UInt32: NWUDPSession]()
        let dispatchGroup = DispatchGroup()
        var socketObservers: [NSKeyValueObservation] = []

        for peer in peers {
            if let endpoint = peer.endpoint,  case let .ipv4(addr) = endpoint.host, endpoint.hasHostAsIPAddress() {
                let endpoint = NetworkExtension.NWHostEndpoint(hostname: "\(endpoint.host)", port: "\(endpoint.port)")

                let session = packetTunnelProvider.createUDPSession(to: endpoint, from: nil)
                let addrBytes = addr.rawValue.withUnsafeBytes { rawPtr in
                    return CFSwapInt32(rawPtr.load(as: UInt32.self))
                }
                
                let observer = session.observe(\.state, options: [.old, .new]) { session, _ in
                        let newState = session.state
                        switch newState {
                        case .ready:
                            dispatchGroup.leave()
                        default:
                            break
                        }
                    }
                if session.state != .ready {
                    dispatchGroup.enter()
                    socketObservers.append(observer)
                } else {
                    observer.invalidate()
                }

                map[addrBytes] = session
            }
        }

        // TODO: add timeout here, and error out if the sockets fail to get ready _soon_ enough
        dispatchGroup.wait()
        for observer in socketObservers {
            observer.invalidate()
        }

        v4SessionMap = map
        initializeUdpSessionReadHandlers()
    }

    private func initializeUdpSessionReadHandlers() {
        let readHandler = {
            [weak self] (traffic: [Data]?, error: (any Error)?) -> Void in
                guard let self, let traffic else { return }

                self.dispatchQueue.async {
                    self.receiveTunnelTraffic(traffic)
                }
            }
        for (_, socket) in self.v4SessionMap {
            socket.setReadHandler(readHandler, maxDatagrams: 100)
        }

        for (_, socket) in self.v6SessionMap {
            socket.setReadHandler(readHandler, maxDatagrams: 100)
        }
    }

    private static func handleUdpSendV6(
        ctx: UnsafeMutableRawPointer?,
        addr: UInt32,
        port: UInt16,
        buffer: UnsafePointer<UInt8>?,
        size: UInt
    ) {

    }


    private static func handleTunSendV4(
        ctx: UnsafeRawPointer?,
        data: UnsafePointer<UInt8>?,
        size: UInt
    ) {
        guard let ctx = ctx else { return }
        guard let data = data else { return }

        let unmanagedInstance = Unmanaged<AbstractTun>.fromOpaque(ctx)
        let abstractTun = unmanagedInstance.takeUnretainedValue()

        let packetBytes = Data(bytes: data, count: Int(size))

        abstractTun.packetTunnelProvider.packetFlow.writePackets([packetBytes], withProtocols: [NSNumber(value:AF_INET)])

        abstractTun.bytesReceived += UInt64(size)
    }

    func block(tunnelConfiguration: TunnelConfiguration) -> Result<(), AbstractTunError> {
        return setConfiguration(tunnelConfiguration)
    }

}
func generateNetworkSettings(tunnelConfiguration: TunnelConfiguration) -> NEPacketTunnelNetworkSettings {
    /* iOS requires a tunnel endpoint, whereas in WireGuard it's valid for
     * a tunnel to have no endpoint, or for there to be many endpoints, in
     * which case, displaying a single one in settings doesn't really
     * make sense. So, we fill it in with this placeholder, which is not
     * a valid IP address that will actually route over the Internet.
     */
    let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

    if !tunnelConfiguration.interface.dnsSearch.isEmpty || !tunnelConfiguration.interface.dns.isEmpty {
        let dnsServerStrings = tunnelConfiguration.interface.dns.map { $0.stringRepresentation }
        let dnsSettings = NEDNSSettings(servers: dnsServerStrings)
        dnsSettings.searchDomains = tunnelConfiguration.interface.dnsSearch
        if !tunnelConfiguration.interface.dns.isEmpty {
            dnsSettings.matchDomains = [""] // All DNS queries must first go through the tunnel's DNS
        }
        networkSettings.dnsSettings = dnsSettings
    }

    let mtu = tunnelConfiguration.interface.mtu ?? 0

    /* 0 means automatic MTU. In theory, we should just do
     * `networkSettings.tunnelOverheadBytes = 80` but in
     * practice there are too many broken networks out there.
     * Instead set it to 1280. Boohoo. Maybe someday we'll
     * add a nob, maybe, or iOS will do probing for us.
     */
    if mtu == 0 {
#if os(iOS)
        networkSettings.mtu = NSNumber(value: 1280)
#elseif os(macOS)
        networkSettings.tunnelOverheadBytes = 80
#else
#error("Unimplemented")
#endif
    } else {
        networkSettings.mtu = NSNumber(value: mtu)
    }

    let (ipv4Addresses, ipv6Addresses) = addresses(tunnelConfiguration: tunnelConfiguration)
    let (ipv4IncludedRoutes, ipv6IncludedRoutes) = includedRoutes(tunnelConfiguration: tunnelConfiguration)

    let ipv4Settings = NEIPv4Settings(addresses: ipv4Addresses.map { $0.destinationAddress }, subnetMasks: ipv4Addresses.map { $0.destinationSubnetMask })
    ipv4Settings.includedRoutes = ipv4IncludedRoutes
    networkSettings.ipv4Settings = ipv4Settings

    let ipv6Settings = NEIPv6Settings(addresses: ipv6Addresses.map { $0.destinationAddress }, networkPrefixLengths: ipv6Addresses.map { $0.destinationNetworkPrefixLength })
    ipv6Settings.includedRoutes = ipv6IncludedRoutes
    networkSettings.ipv6Settings = ipv6Settings

    return networkSettings
}

private func addresses(tunnelConfiguration: TunnelConfiguration) -> ([NEIPv4Route], [NEIPv6Route]) {
    var ipv4Routes = [NEIPv4Route]()
    var ipv6Routes = [NEIPv6Route]()
    for addressRange in tunnelConfiguration.interface.addresses {
        if addressRange.address is IPv4Address {
            ipv4Routes.append(NEIPv4Route(destinationAddress: "\(addressRange.address)", subnetMask: "\(addressRange.subnetMask())"))
        } else if addressRange.address is IPv6Address {
            /* Big fat ugly hack for broken iOS networking stack: the smallest prefix that will have
             * any effect on iOS is a /120, so we clamp everything above to /120. This is potentially
             * very bad, if various network parameters were actually relying on that subnet being
             * intentionally small. TODO: talk about this with upstream iOS devs.
             */
            ipv6Routes.append(NEIPv6Route(destinationAddress: "\(addressRange.address)", networkPrefixLength: NSNumber(value: min(120, addressRange.networkPrefixLength))))
        }
    }
    return (ipv4Routes, ipv6Routes)
}

private func includedRoutes(tunnelConfiguration: TunnelConfiguration) -> ([NEIPv4Route], [NEIPv6Route]) {
    var ipv4IncludedRoutes = [NEIPv4Route]()
    var ipv6IncludedRoutes = [NEIPv6Route]()

    for addressRange in tunnelConfiguration.interface.addresses {
        if addressRange.address is IPv4Address {
            let route = NEIPv4Route(destinationAddress: "\(addressRange.maskedAddress())", subnetMask: "\(addressRange.subnetMask())")
            route.gatewayAddress = "\(addressRange.address)"
            ipv4IncludedRoutes.append(route)
        } else if addressRange.address is IPv6Address {
            let route = NEIPv6Route(destinationAddress: "\(addressRange.maskedAddress())", networkPrefixLength: NSNumber(value: addressRange.networkPrefixLength))
            route.gatewayAddress = "\(addressRange.address)"
            ipv6IncludedRoutes.append(route)
        }
    }

    for peer in tunnelConfiguration.peers {
        for addressRange in peer.allowedIPs {
            if addressRange.address is IPv4Address {
                ipv4IncludedRoutes.append(NEIPv4Route(destinationAddress: "\(addressRange.address)", subnetMask: "\(addressRange.subnetMask())"))
            } else if addressRange.address is IPv6Address {
                ipv6IncludedRoutes.append(NEIPv6Route(destinationAddress: "\(addressRange.address)", networkPrefixLength: NSNumber(value: addressRange.networkPrefixLength)))
            }
        }
    }
    return (ipv4IncludedRoutes, ipv6IncludedRoutes)
}




enum AbstractTunError: Error {
    case initializationError
    case noPeers
    case setNetworkSettings(Error)
    case setNetworkSettingsTimeout
    case noOpenSocket
}

//class UdpSession {
//    private var session: NWUDPSession
//    var ready: Bool
//    var dispatchGroup: DispatchGroup
//
//    init(packetTunnelProvider: PacketTunnelProvider, hostname: String, port: String) {
//
//        let endpoint = NetworkExtension.NWHostEndpoint(hostname: hostname, port: port)
//        session = packetTunnelProvider.createUDPSession(to: endpoint, from: nil)
//
//        ready = session.state == .ready
//    }
//
//    func waitToBeReady() {
//
//    }
//
//    func sendData(data: [Data], completion: ((any Error)?) -> Void) {
//        self.waitToBeReady()
//
//        dispatchGroup.enter()
//        session.writeMultipleDatagrams(data) { [weak self] error in
//            self?.dispatchGroup.leave()
//            completion(error)
//        }
//
//        dispatchGroup.wait()
//    }
//
//    func setReadHandler(maxDatagrams: Int, readHandler: (traffic: [Data]?, error: (any Error)?)) {
//        session.setReadHandler(readHandler, maxDatagrams: maxDatagrams)
//    }
//}