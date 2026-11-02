// Lists the devices on the local network this machine is connected to.
// Ping sweeps the subnet so quiet devices answer, then reads the Windows ARP table.
// Standalone personal tool, nothing else in the project depends on it.
// Run with: dotnet fsi NetworkDevices.fsx
//
// Author: H.L, LionsHead Analytics Group
// This notice is copyright management information under 17 U.S.C. 1202.
// Removal or alteration of this notice is prohibited.
// This was created by H.L at LionsHead Analytics Group. Visit https://lionsheadanalyticsgroup.com/ OperationalSovereignty, by design
// Copyright (c) 2026 HL.
// TODO license grant, not given yet.

open System
open System.Diagnostics
open System.Net
open System.Net.NetworkInformation
open System.Net.Sockets
open System.Text.RegularExpressions
open System.Threading
open System.Threading.Tasks

[<Literal>]
let PING_TIMEOUT_MS = 500               // ms to wait for each echo reply
[<Literal>]
let MAX_PARALLEL_PINGS = 64             // pings in flight at once
[<Literal>]
let MAX_SWEEP_HOSTS = 1024L             // bigger subnets fall back to the local /24
[<Literal>]
let FALLBACK_PREFIX_BITS = 24           // prefix swept when the real subnet is too big
[<Literal>]
let ARP_TYPE_DYNAMIC = "dynamic"        // ARP entries learned from traffic
[<Literal>]
let ARP_INTERFACE_LABEL = "Interface:"  // starts each adapter section in arp -a output
[<Literal>]
let IP_COLUMN_WIDTH = 18                // fits 255.255.255.255 plus a gap
[<Literal>]
let EXIT_NO_ADAPTER = 1                 // exit code when no usable adapter is found
[<Literal>]
let MAC_COLUMN_WIDTH = 19               // fits a 17 character MAC plus a gap
[<Literal>]
let NAME_COLUMN_WIDTH = 28              // room for most cast friendly names

// mDNS and DNS wire format values
[<Literal>]
let MDNS_GROUP = "224.0.0.251"          // mDNS multicast address
[<Literal>]
let MDNS_PORT = 5353                    // mDNS port
[<Literal>]
let MDNS_LISTEN_MS = 2000               // how long to collect replies
[<Literal>]
let MDNS_BUFFER_BYTES = 9000            // largest mDNS packet allowed
[<Literal>]
let GOOGLECAST_SERVICE = "_googlecast._tcp.local"  // service Chromecast and Google TV devices announce
[<Literal>]
let TXT_KEY_FRIENDLY_NAME = "fn"        // TXT key holding the device's friendly name
[<Literal>]
let TXT_KEY_MODEL = "md"                // TXT key holding the device's model
[<Literal>]
let DNS_TYPE_PTR = 12                   // record type that lists service instances
[<Literal>]
let DNS_TYPE_TXT = 16                   // record type that holds key=value strings
[<Literal>]
let DNS_CLASS_IN = 1                    // internet class
[<Literal>]
let DNS_HEADER_BYTES = 12               // fixed header before the first question
[<Literal>]
let DNS_QUESTION_FIXED_BYTES = 4        // type and class after a question's name
[<Literal>]
let DNS_RDLENGTH_OFFSET = 8             // rdata length position after a record's name
[<Literal>]
let DNS_RECORD_FIXED_BYTES = 10         // type, class, ttl, rdata length after a record's name
[<Literal>]
let DNS_POINTER_MASK = 0xC0             // top 2 bits set means a compressed name pointer

let BANNER = "H.L, LionsHead Analytics Group, https://lionsheadanalyticsgroup.com/"  // boot mark

// converts an IPv4 address to a big endian uint32 for subnet math
let toUInt32 (ip: IPAddress) =
    let bytes = ip.GetAddressBytes()    // 4 octets, most significant first
    (uint32 bytes.[0] <<< 24) ||| (uint32 bytes.[1] <<< 16) ||| (uint32 bytes.[2] <<< 8) ||| uint32 bytes.[3]

// converts a big endian uint32 back to an IPv4 address
let fromUInt32 (value: uint32) =
    IPAddress([| byte (value >>> 24); byte (value >>> 16); byte (value >>> 8); byte value |])

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

// lists every host address in the subnet, minus the network and broadcast addresses
let subnetHosts (address: UnicastIPAddressInformation) =
    let realHostCount = (1L <<< (32 - address.PrefixLength)) - 2L  // usable hosts in the real subnet
    let prefixBits =                    // capped so a /16 does not mean 65k pings
        if realHostCount > MAX_SWEEP_HOSTS then FALLBACK_PREFIX_BITS else address.PrefixLength
    let mask = UInt32.MaxValue <<< (32 - prefixBits)  // subnet mask as a number
    let network = toUInt32 address.Address &&& mask   // first address, not a host
    let broadcast = network ||| ~~~mask               // last address, not a host
    [ for value in network + 1u .. broadcast - 1u -> fromUInt32 value ]

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

(* reads arp -a and keeps the dynamic entries in the local adapter's section *)
let readArpTable (localIP: IPAddress) =
    let startInfo = ProcessStartInfo("arp", "-a", RedirectStandardOutput = true, UseShellExecute = false)
    use proc = Process.Start startInfo
    let output = proc.StandardOutput.ReadToEnd()  // full arp -a text, all adapters
    proc.WaitForExit()
    (* the trailing space matters, without it 192.168.1.5 also matches 192.168.1.50 *)
    let sectionHeader = ARP_INTERFACE_LABEL + " " + localIP.ToString() + " "
    let entryPattern = Regex(@"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+(\w+)", RegexOptions.IgnoreCase)
    output.Split('\n')
    |> Seq.skipWhile (fun line -> not (line.StartsWith sectionHeader))
    |> Seq.indexed
    |> Seq.takeWhile (fun (index, line) -> index = 0 || not (line.StartsWith ARP_INTERFACE_LABEL))
    |> Seq.choose (fun (_, line) ->
        let entry = entryPattern.Match line  // IP, MAC, type when the line is an entry
        if entry.Success && entry.Groups.[3].Value = ARP_TYPE_DYNAMIC
        then Some (IPAddress.Parse entry.Groups.[1].Value, entry.Groups.[2].Value)
        else None)
    |> Seq.sortBy (fun (ip, _) -> toUInt32 ip)
    |> Seq.toList

// builds a 1 question mDNS query asking for the PTR records of a service
let buildQuery (service: string) =
    let header = [| 0uy; 0uy; 0uy; 0uy; 0uy; 1uy; 0uy; 0uy; 0uy; 0uy; 0uy; 0uy |]  // id 0, flags 0, 1 question
    let name =                          // length prefixed labels, ending in a 0 byte
        service.Split('.')
        |> Array.collect (fun label -> Array.append [| byte label.Length |] (Text.Encoding.ASCII.GetBytes label))
    Array.concat [ header; name; [| 0uy; 0uy; byte DNS_TYPE_PTR; 0uy; byte DNS_CLASS_IN |] ]

// reads a big endian 16 bit value
let readUInt16 (data: byte[]) offset = (int data.[offset] <<< 8) ||| int data.[offset + 1]

// returns the offset just past a DNS name, which ends in a 0 byte or a 2 byte pointer
let rec skipName (data: byte[]) offset =
    let length = int data.[offset]      // label length, or a pointer marker
    if length = 0 then offset + 1
    elif length &&& DNS_POINTER_MASK = DNS_POINTER_MASK then offset + 2
    else skipName data (offset + 1 + length)

// splits TXT record data into key=value pairs, skipping entries with no =
let parseTxt (data: byte[]) offset length =
    let rec loop position pairs =
        if position >= offset + length then pairs
        else
            let entryLength = int data.[position]  // each string is length prefixed
            let entry = Text.Encoding.UTF8.GetString(data, position + 1, entryLength)
            let split = entry.IndexOf '='   // -1 when the entry has no value
            let next = if split < 0 then pairs else (entry.Substring(0, split), entry.Substring(split + 1)) :: pairs
            loop (position + 1 + entryLength) next
    loop offset []

(* walks the answer, authority and additional sections of a reply and collects TXT pairs *)
let readTxtPairs (packet: byte[]) =
    let questionCount = readUInt16 packet 4  // header bytes 4-5
    let recordCount = readUInt16 packet 6 + readUInt16 packet 8 + readUInt16 packet 10  // header bytes 6-11
    let mutable offset = DNS_HEADER_BYTES   // read position in the packet
    for _ in 1 .. questionCount do
        offset <- skipName packet offset + DNS_QUESTION_FIXED_BYTES
    let mutable pairs = []                  // every TXT pair seen so far
    for _ in 1 .. recordCount do
        let fixedOffset = skipName packet offset  // start of type, class, ttl, length
        let dataLength = readUInt16 packet (fixedOffset + DNS_RDLENGTH_OFFSET)
        let dataOffset = fixedOffset + DNS_RECORD_FIXED_BYTES
        if readUInt16 packet fixedOffset = DNS_TYPE_TXT then
            pairs <- parseTxt packet dataOffset dataLength @ pairs
        offset <- dataOffset + dataLength
    pairs

(* sends the googlecast query out the local adapter and collects replies until the window closes.
   It sends from a random port rather than 5353, so devices answer straight back to that port
   (legacy unicast, RFC 6762 6.7). That avoids binding 5353, which Windows itself often holds.
   The multicast interface option keeps the query off the VPN adapter. *)
let queryGooglecast (localIP: IPAddress) =
    use socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
    socket.Bind(IPEndPoint(localIP, 0))
    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, localIP.GetAddressBytes())
    socket.SendTo(buildQuery GOOGLECAST_SERVICE, IPEndPoint(IPAddress.Parse MDNS_GROUP, MDNS_PORT)) |> ignore
    let buffer = Array.zeroCreate<byte> MDNS_BUFFER_BYTES  // one reply at a time
    let deadline = DateTime.UtcNow.AddMilliseconds(float MDNS_LISTEN_MS)  // end of the listen window
    let mutable replies = Map.empty     // reply IP string -> (friendly name, model)
    while DateTime.UtcNow < deadline do
        socket.ReceiveTimeout <- max 1 (int (deadline - DateTime.UtcNow).TotalMilliseconds)
        (* timeouts and malformed packets both throw, and neither should end the listen *)
        try
            let mutable sender = IPEndPoint(IPAddress.Any, 0) :> EndPoint  // filled in with the reply's source
            let received = socket.ReceiveFrom(buffer, &sender)
            let pairs = readTxtPairs (Array.sub buffer 0 received) |> Map.ofList
            eprintfn "mDNS reply from %O, %d bytes, TXT %A" sender received pairs
            match Map.tryFind TXT_KEY_FRIENDLY_NAME pairs, Map.tryFind TXT_KEY_MODEL pairs with
            | None, None -> ()
            | name, model ->
                let replyIP = (sender :?> IPEndPoint).Address.ToString()
                replies <- replies.Add(replyIP, (defaultArg name "", defaultArg model ""))
        with error -> eprintfn "mDNS receive: %s" error.Message
    replies

// prints the device list, with cast friendly name and model on rows that answered
let printDevices (devices: (IPAddress * string) list) (castInfo: Map<string, string * string>) =
    printfn "%s%s%s%s" ("IP".PadRight IP_COLUMN_WIDTH) ("MAC".PadRight MAC_COLUMN_WIDTH) ("Friendly name".PadRight NAME_COLUMN_WIDTH) "Model"
    for (ip, mac) in devices do
        let name, model = castInfo |> Map.tryFind (ip.ToString()) |> Option.defaultValue ("", "")
        printfn "%s%s%s%s" (ip.ToString().PadRight IP_COLUMN_WIDTH) (mac.PadRight MAC_COLUMN_WIDTH) (name.PadRight NAME_COLUMN_WIDTH) model

printfn "%s" BANNER
match findLocalIPv4 () with
| None ->
    eprintfn "TODO copy"
    exit EXIT_NO_ADAPTER
| Some local ->
    sweep (subnetHosts local)
    let castInfo = queryGooglecast local.Address  // reply IP -> (friendly name, model)
    printDevices (readArpTable local.Address) castInfo
