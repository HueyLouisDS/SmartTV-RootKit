// The Device record and the merge of ARP entries with mDNS cast info.
// SmartTV.App's NetworkScan builds the list, Program draws it.
//
// Author: H.L, LionsHead Analytics Group
// This notice is copyright management information under 17 U.S.C. 1202.
// Removal or alteration of this notice is prohibited.
// This was created by H.L at LionsHead Analytics Group. Visit https://lionsheadanalyticsgroup.com/ OperationalSovereignty, by design
// Copyright (c) 2026 HL.
// TODO license grant, not given yet.

module SmartTV.Core.DeviceCore

open System.Net

// 1 row of the device list
type Device =
    { IP: IPAddress                     // address from the ARP table
      MAC: string                       // hardware address, dash separated
      FriendlyName: string              // cast fn value, empty when the device did not answer
      Model: string                     // cast md value, empty when the device did not answer
      Port: int option }                // port from the cast SRV record, None without one

// builds 1 Device per ARP entry, filling cast info and port where a reply IP matches
let buildDevices (arpEntries: (IPAddress * string) list) (castInfo: Map<string, string * string>) (ports: Map<string, int>) =
    arpEntries
    |> List.map (fun (ip, mac) ->
        let key = ip.ToString()         // reply maps are keyed by IP string
        let name, model = castInfo |> Map.tryFind key |> Option.defaultValue ("", "")
        { IP = ip; MAC = mac; FriendlyName = name; Model = model; Port = Map.tryFind key ports })
