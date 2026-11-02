// Subnet math for the ping sweep, pure so it runs without a network.
// SmartTV.App's NetworkScan calls subnetHosts with the adapter's address and prefix.
//
// Author: H.L, LionsHead Analytics Group
// This notice is copyright management information under 17 U.S.C. 1202.
// Removal or alteration of this notice is prohibited.
// This was created by H.L at LionsHead Analytics Group. Visit https://lionsheadanalyticsgroup.com/ OperationalSovereignty, by design
// Copyright (c) 2026 HL.
// TODO license grant, not given yet.

module SmartTV.Core.SubnetCore

open System
open System.Net

[<Literal>]
let MAX_SWEEP_HOSTS = 1024L             // bigger subnets fall back to the local /24
[<Literal>]
let FALLBACK_PREFIX_BITS = 24           // prefix swept when the real subnet is too big

// converts an IPv4 address to a big endian uint32 for subnet math
let toUInt32 (ip: IPAddress) =
    let bytes = ip.GetAddressBytes()    // 4 octets, most significant first
    (uint32 bytes.[0] <<< 24) ||| (uint32 bytes.[1] <<< 16) ||| (uint32 bytes.[2] <<< 8) ||| uint32 bytes.[3]

// converts a big endian uint32 back to an IPv4 address
let fromUInt32 (value: uint32) =
    IPAddress([| byte (value >>> 24); byte (value >>> 16); byte (value >>> 8); byte value |])

// lists every host address in the subnet, minus the network and broadcast addresses
let subnetHosts (address: IPAddress) (prefixLength: int) =
    let realHostCount = (1L <<< (32 - prefixLength)) - 2L  // usable hosts in the real subnet
    let prefixBits =                    // capped so a /16 does not mean 65k pings
        if realHostCount > MAX_SWEEP_HOSTS then FALLBACK_PREFIX_BITS else prefixLength
    let mask = UInt32.MaxValue <<< (32 - prefixBits)  // subnet mask as a number
    let network = toUInt32 address &&& mask           // first address, not a host
    let broadcast = network ||| ~~~mask               // last address, not a host
    [ for value in network + 1u .. broadcast - 1u -> fromUInt32 value ]
