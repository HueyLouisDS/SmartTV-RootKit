// Builds the googlecast mDNS query and reads fn and md out of the TXT records in a reply.
// SmartTV.App's NetworkScan sends and receives the packets, this only handles bytes.
//
// Author: H.L, LionsHead Analytics Group
// This notice is copyright management information under 17 U.S.C. 1202.
// Removal or alteration of this notice is prohibited.
// This was created by H.L at LionsHead Analytics Group. Visit https://lionsheadanalyticsgroup.com/ OperationalSovereignty, by design
// Copyright (c) 2026 HL.
// TODO license grant, not given yet.

module SmartTV.Core.MdnsCore

open System.Text

[<Literal>]
let GOOGLECAST_SERVICE = "_googlecast._tcp.local"  // service Chromecast and Google TV devices announce
[<Literal>]
let TXT_KEY_FRIENDLY_NAME = "fn"        // TXT key holding the device's friendly name
[<Literal>]
let TXT_KEY_MODEL = "md"                // TXT key holding the device's model

// DNS wire format values
[<Literal>]
let DNS_TYPE_PTR = 12                   // record type that lists service instances
[<Literal>]
let DNS_TYPE_TXT = 16                   // record type that holds key=value strings
[<Literal>]
let DNS_TYPE_SRV = 33                   // record type that holds a service's port and host
[<Literal>]
let SRV_PORT_OFFSET = 4                 // port position in SRV data, after priority and weight
[<Literal>]
let DNS_CLASS_IN = 1                   // internet class
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

// builds a 1 question mDNS query asking for the PTR records of a service
let buildQuery (service: string) =
    let header = [| 0uy; 0uy; 0uy; 0uy; 0uy; 1uy; 0uy; 0uy; 0uy; 0uy; 0uy; 0uy |]  // id 0, flags 0, 1 question
    let name =                          // length prefixed labels, ending in a 0 byte
        service.Split('.')
        |> Array.collect (fun label -> Array.append [| byte label.Length |] (Encoding.ASCII.GetBytes label))
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
            let entry = Encoding.UTF8.GetString(data, position + 1, entryLength)
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

(* walks the same sections as readTxtPairs and returns the port from the first SRV record.
   None when the reply carried no SRV record. *)
let readSrvPort (packet: byte[]) =
    let questionCount = readUInt16 packet 4  // header bytes 4-5
    let recordCount = readUInt16 packet 6 + readUInt16 packet 8 + readUInt16 packet 10  // header bytes 6-11
    let mutable offset = DNS_HEADER_BYTES   // read position in the packet
    for _ in 1 .. questionCount do
        offset <- skipName packet offset + DNS_QUESTION_FIXED_BYTES
    let mutable port = None                 // first SRV port seen
    for _ in 1 .. recordCount do
        let fixedOffset = skipName packet offset  // start of type, class, ttl, length
        let dataLength = readUInt16 packet (fixedOffset + DNS_RDLENGTH_OFFSET)
        let dataOffset = fixedOffset + DNS_RECORD_FIXED_BYTES
        if port.IsNone && readUInt16 packet fixedOffset = DNS_TYPE_SRV then
            port <- Some (readUInt16 packet (dataOffset + SRV_PORT_OFFSET))
        offset <- dataOffset + dataLength
    port

[<Literal>]
let DNS_FLAG_RESPONSE = 0x80            // top bit of header byte 2, set on answers, clear on queries

// true when the packet is an answer, false for queries, including the app's own looped back
let isResponse (packet: byte[]) =
    packet.Length > 2 && (int packet.[2] &&& DNS_FLAG_RESPONSE) <> 0

// pulls (friendly name, model) from TXT pairs, None when neither key is present
let castInfoFromPairs (pairs: Map<string, string>) =
    match Map.tryFind TXT_KEY_FRIENDLY_NAME pairs, Map.tryFind TXT_KEY_MODEL pairs with
    | None, None -> None
    | name, model -> Some (defaultArg name "", defaultArg model "")
