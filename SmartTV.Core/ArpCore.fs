// Parses the ARP table into (IP, MAC) pairs, arp -a text on Windows and /proc/net/arp on Linux.
// SmartTV.App's NetworkScan reads the right source for the OS and hands the text here.
//
// Author: H.L, LionsHead Analytics Group
// This notice is copyright management information under 17 U.S.C. 1202.
// Removal or alteration of this notice is prohibited.
// This was created by H.L at LionsHead Analytics Group. Visit https://lionsheadanalyticsgroup.com/ OperationalSovereignty, by design
// Copyright (c) 2026 HL.
// TODO license grant, not given yet.

module SmartTV.Core.ArpCore

open System
open System.Net
open System.Text.RegularExpressions
open SmartTV.Core.SubnetCore

[<Literal>]
let ARP_TYPE_DYNAMIC = "dynamic"        // ARP entries learned from traffic
[<Literal>]
let ARP_INTERFACE_LABEL = "Interface:"  // starts each adapter section in arp -a output
[<Literal>]
let PROC_ARP_FLAG_COMPLETE = 0x2        // /proc/net/arp flag for a resolved entry

(* keeps the dynamic entries in the local adapter's section, sorted by address *)
let parseArpTable (output: string) (localIP: IPAddress) =
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

(* reads /proc/net/arp on Linux and keeps resolved entries in the local subnet, sorted by address.
   Linux lists every interface in 1 table, so the subnet check stands in for the section header.
   MACs come as aa:bb:cc and are rewritten to aa-bb-cc so stored names match the Windows form. *)
let parseProcNetArp (text: string) (localIP: IPAddress) (prefixLength: int) =
    let mask = UInt32.MaxValue <<< (32 - prefixLength)  // subnet mask as a number
    let network = toUInt32 localIP &&& mask             // local subnet's first address
    text.Split('\n')
    |> Seq.skip 1                       // header row
    |> Seq.map (fun line -> line.Split([| ' ' |], StringSplitOptions.RemoveEmptyEntries))
    |> Seq.filter (fun columns -> columns.Length >= 4)
    |> Seq.choose (fun columns ->
        let ip = IPAddress.Parse columns.[0]
        let flags = Convert.ToInt32(columns.[2], 16)  // hex, like 0x2
        if flags &&& PROC_ARP_FLAG_COMPLETE <> 0 && (toUInt32 ip &&& mask) = network
        then Some (ip, columns.[3].Replace(':', '-').ToLowerInvariant())
        else None)
    |> Seq.sortBy (fun (ip, _) -> toUInt32 ip)
    |> Seq.toList
