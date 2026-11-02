// The network I/O half of the scan, adapter lookup, ping sweep, arp and the mDNS socket.
// Parsing and math live in SmartTV.Core, Program.fs calls scan and draws the result.
// Nothing in here touches the screen except the mDNS debug lines on stderr.
//
// Author: H.L, LionsHead Analytics Group
// This notice is copyright management information under 17 U.S.C. 1202.
// Removal or alteration of this notice is prohibited.
// This was created by H.L at LionsHead Analytics Group. Visit https://lionsheadanalyticsgroup.com/ OperationalSovereignty, by design
// Copyright (c) 2026 HL.
// TODO license grant, not given yet.

module SmartTV.App.NetworkScan

open System
open System.Diagnostics
open System.Net
open System.Net.NetworkInformation
open System.Net.Sockets
open System.Threading
open System.Threading.Tasks
open SmartTV.Core.SubnetCore
open SmartTV.Core.ArpCore
open SmartTV.Core.MdnsCore
open SmartTV.Core.DeviceCore

[<Literal>]
let PING_TIMEOUT_MS = 500               // ms to wait for each echo reply
[<Literal>]
let MAX_PARALLEL_PINGS = 64             // pings in flight at once
[<Literal>]
let MDNS_GROUP = "224.0.0.251"          // mDNS multicast address
[<Literal>]
let MDNS_PORT = 5353                    // mDNS port
[<Literal>]
let MDNS_LISTEN_MS = 2000               // how long to collect replies
[<Literal>]
let MDNS_BUFFER_BYTES = 9000            // largest mDNS packet allowed
[<Literal>]
let MDNS_QUERY_SENDS = 3                // queries per listen window, UDP never resends a lost one

// picks the first up IPv4 adapter with a real gateway, which is the wifi or LAN one
let findLocalIPv4 () =
    (* VPN adapters like ProtonVPN report 0.0.0.0 as a gateway, which is not a real one *)
    let isRealIPv4Gateway (gateway: GatewayIPAddressInformation) =
        gateway.Address.AddressFamily = AddressFamily.InterNetwork && not (gateway.Address.Equals IPAddress.Any)
    let hasIPv4Gateway (props: IPInterfaceProperties) =
        props.GatewayAddresses |> Seq.exists isRealIPv4Gateway
    NetworkInterface.GetAllNetworkInterfaces()
    |> Seq.filter (fun nic -> nic.OperationalStatus = OperationalStatus.Up)
    |> Seq.filter (fun nic -> nic.NetworkInterfaceType <> NetworkInterfaceType.Loopback)
    |> Seq.map (fun nic -> nic.GetIPProperties())
    |> Seq.filter hasIPv4Gateway
    |> Seq.collect (fun props -> props.UnicastAddresses)
    |> Seq.tryFind (fun addr -> addr.Address.AddressFamily = AddressFamily.InterNetwork)

(* pings every host so devices that have been quiet land in the ARP table *)
let sweep (hosts: IPAddress list) =
    use gate = new SemaphoreSlim(MAX_PARALLEL_PINGS)  // caps concurrent pings
    let pingOne (host: IPAddress) =
        task {
            do! gate.WaitAsync()
            try
                use ping = new Ping()
                try
                    let! _ = ping.SendPingAsync(host, PING_TIMEOUT_MS)
                    ()
                with _ -> ()
            finally
                gate.Release() |> ignore
        }
    (hosts |> List.map pingOne |> Task.WhenAll).Wait()

[<Literal>]
let ADAPTER_TYPE_PROP_VIRTUAL = 53      // Windows ifType for virtual adapters, missing from .NET's enum

(* Windows clients name adapters VPN, TAP-Windows, WireGuard, Wintun, OpenVPN.
   Linux names them tun0, wg0, ppp0, proton0, and the adapter type there is often Unknown. *)
let VPN_NAME_HINTS = [ "VPN"; "TAP-Windows"; "WireGuard"; "Wintun"; "OpenVPN"; "tun"; "wg"; "ppp"; "proton" ]

(* true when any up adapter looks like a VPN tunnel.
   ProtonVPN reports type 53 rather than Ppp or Tunnel, so the type alone misses it,
   and the name hints catch clients whose adapter type looks like plain Ethernet. *)
let isVPNConnected () =
    let looksLikeVPN (nic: NetworkInterface) =
        let typeMatch =                 // tunnel style adapter types
            nic.NetworkInterfaceType = NetworkInterfaceType.Ppp
            || nic.NetworkInterfaceType = NetworkInterfaceType.Tunnel
            || int nic.NetworkInterfaceType = ADAPTER_TYPE_PROP_VIRTUAL
        let nameMatch =                 // a known VPN word in the name or description
            VPN_NAME_HINTS
            |> List.exists (fun hint ->
                nic.Name.Contains(hint, StringComparison.OrdinalIgnoreCase)
                || nic.Description.Contains(hint, StringComparison.OrdinalIgnoreCase))
        typeMatch || nameMatch
    NetworkInterface.GetAllNetworkInterfaces()
    |> Seq.filter (fun nic -> nic.OperationalStatus = OperationalStatus.Up)
    |> Seq.exists looksLikeVPN

// pings 1 address and reports whether it answered, any error counts as no answer
let pingOnce (host: IPAddress) =
    use ping = new Ping()
    try ping.Send(host, PING_TIMEOUT_MS).Status = IPStatus.Success
    with _ -> false

// runs arp -a and returns its full text, all adapters
let runArp () =
    let startInfo = ProcessStartInfo("arp", "-a", RedirectStandardOutput = true, UseShellExecute = false)
    use proc = Process.Start startInfo
    let output = proc.StandardOutput.ReadToEnd()  // read before WaitForExit so a full pipe cannot block
    proc.WaitForExit()
    output

// raw socket option numbers, .NET has no name for SO_REUSEPORT and the values differ per OS
[<Literal>]
let LINUX_SOL_SOCKET = 1                // socket level on Linux
[<Literal>]
let LINUX_SO_REUSEPORT = 15             // SO_REUSEPORT on Linux
[<Literal>]
let MACOS_SOL_SOCKET = 0xFFFF           // socket level on macOS
[<Literal>]
let MACOS_SO_REUSEPORT = 0x0200         // SO_REUSEPORT on macOS

(* asks for SO_REUSEPORT on Linux and macOS, nothing on Windows where ReuseAddress is enough.
   macOS's mDNSResponder holds 5353 with SO_REUSEPORT and will not share without it, and
   Linux responders that set it do the same. A failure is logged, not thrown, since the
   bind's own fallback handles a port that still cannot be shared. *)
let allowPortSharing (socket: Socket) =
    let enabled = BitConverter.GetBytes 1  // option value 1 as a native int
    try
        if OperatingSystem.IsLinux() then
            socket.SetRawSocketOption(LINUX_SOL_SOCKET, LINUX_SO_REUSEPORT, ReadOnlySpan<byte>(enabled))
        elif OperatingSystem.IsMacOS() then
            socket.SetRawSocketOption(MACOS_SOL_SOCKET, MACOS_SO_REUSEPORT, ReadOnlySpan<byte>(enabled))
    with error -> eprintfn "mDNS SO_REUSEPORT not set: %s" error.Message

(*-------- This is critical --------*)
(* opens the mDNS socket on shared port 5353 and joins the mDNS group 224.0.0.251.
   Devices answer a query sent from 5353 to the whole group, which every mDNS device supports,
   so joining the group is what makes replies arrive at all.
   ReuseAddress and allowPortSharing must both run before Bind. The OS responder already holds
   5353 (Windows DNS Client, Linux avahi, macOS mDNSResponder) and without sharing the bind fails.
   If 5353 still cannot be bound, it falls back to a random port, where only devices that
   answer directly (legacy unicast, RFC 6762 6.7) will reply. The multicast interface option
   keeps queries off the VPN adapter. *)
let openMdnsSocket (localIP: IPAddress) =
    let socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true)
    allowPortSharing socket
    try
        socket.Bind(IPEndPoint(IPAddress.Any, MDNS_PORT))
        try
            socket.SetSocketOption(
                SocketOptionLevel.IP, SocketOptionName.AddMembership, MulticastOption(IPAddress.Parse MDNS_GROUP, localIP))
        with error -> eprintfn "mDNS group join failed, only direct replies will arrive: %s" error.Message
    with error ->
        eprintfn "mDNS port %d not shareable, falling back to direct replies: %s" MDNS_PORT error.Message
        socket.Bind(IPEndPoint(localIP, 0))
    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, localIP.GetAddressBytes())
    socket

(* sends the googlecast query MDNS_QUERY_SENDS times across the listen window and collects replies.
   Each receive waits only until the next send is due, so sends go out on time.
   Queries (the app's own, looped back, or other hosts') are skipped by isResponse.
   A port is kept only from replies that also carry fn or md, since the group also hears
   announcements from printers and speakers whose SRV ports are not cast ports. *)
let queryGooglecast (localIP: IPAddress) =
    use socket = openMdnsSocket localIP
    let query = buildQuery GOOGLECAST_SERVICE  // same bytes every send
    let group = IPEndPoint(IPAddress.Parse MDNS_GROUP, MDNS_PORT)  // where queries go
    let buffer = Array.zeroCreate<byte> MDNS_BUFFER_BYTES  // one reply at a time
    let started = DateTime.UtcNow       // start of the listen window
    let deadline = started.AddMilliseconds(float MDNS_LISTEN_MS)  // end of the listen window
    let sendInterval = MDNS_LISTEN_MS / MDNS_QUERY_SENDS  // ms between sends
    let mutable sent = 0                // queries sent so far
    let mutable replies = Map.empty     // reply IP string -> (friendly name, model)
    let mutable ports = Map.empty       // reply IP string -> announced SRV port
    while DateTime.UtcNow < deadline do
        let elapsed = int (DateTime.UtcNow - started).TotalMilliseconds  // ms into the window
        if sent < MDNS_QUERY_SENDS && elapsed >= sent * sendInterval then
            socket.SendTo(query, group) |> ignore
            sent <- sent + 1
        let untilSend = if sent < MDNS_QUERY_SENDS then sent * sendInterval - elapsed else MDNS_LISTEN_MS
        let untilDeadline = int (deadline - DateTime.UtcNow).TotalMilliseconds
        socket.ReceiveTimeout <- max 1 (min untilSend untilDeadline)
        (* timeouts are expected every send interval and stay quiet, other errors are logged *)
        try
            let mutable sender = IPEndPoint(IPAddress.Any, 0) :> EndPoint  // filled in with the reply's source
            let received = socket.ReceiveFrom(buffer, &sender)
            let packet = Array.sub buffer 0 received  // just this reply's bytes
            if isResponse packet then
                let replyIP = (sender :?> IPEndPoint).Address.ToString()
                let pairs = readTxtPairs packet |> Map.ofList
                let port = readSrvPort packet   // None when the reply had no SRV record
                eprintfn "mDNS reply from %O, %d bytes, TXT %A, port %A" sender received pairs port
                match castInfoFromPairs pairs with
                | None -> ()
                | Some info ->
                    replies <- replies.Add(replyIP, info)
                    match port with
                    | Some value -> ports <- ports.Add(replyIP, value)
                    | None -> ()
        with
        | :? SocketException as error when error.SocketErrorCode = SocketError.TimedOut -> ()
        | error -> eprintfn "mDNS receive: %s" error.Message
    replies, ports

[<Literal>]
let PROC_NET_ARP = "/proc/net/arp"      // Linux kernel's ARP table

// reads the ARP table for the OS, arp -a on Windows, /proc/net/arp elsewhere (Linux)
let readArpEntries (local: UnicastIPAddressInformation) =
    if OperatingSystem.IsWindows() then parseArpTable (runArp ()) local.Address
    else parseProcNetArp (IO.File.ReadAllText PROC_NET_ARP) local.Address local.PrefixLength

// runs the full scan and returns 1 Device per ARP entry, with cast info where a reply matched
let scan (local: UnicastIPAddressInformation) =
    sweep (subnetHosts local.Address local.PrefixLength)
    let castInfo, ports = queryGooglecast local.Address  // reply IP -> (name, model), reply IP -> port
    buildDevices (readArpEntries local) castInfo ports
