// Entry point. Opens on a start menu moved with the up and down arrows, Esc or q quits.
// Discover devices scans, lists with each device's announced port, and pings the picked device,
// which becomes the selected one.
// Root device stays grey until a device is selected. The prompt names the device by its mDNS name.
// The scan lives in NetworkScan.fs, Device in SmartTV.Core.
//
// Author: H.L, LionsHead Analytics Group
// This notice is copyright management information under 17 U.S.C. 1202.
// Removal or alteration of this notice is prohibited.
// This was created by H.L at LionsHead Analytics Group. Visit https://lionsheadanalyticsgroup.com/ OperationalSovereignty, by design
// Copyright (c) 2026 HL.
// TODO license grant, not given yet.

module SmartTV.App.Program

open System
open SmartTV.Core.DeviceCore
open SmartTV.App.NetworkScan

[<Literal>]
let IP_COLUMN_WIDTH = 18                // fits 255.255.255.255 plus a gap
[<Literal>]
let MAC_COLUMN_WIDTH = 19               // fits a 17 character MAC plus a gap
[<Literal>]
let NAME_COLUMN_WIDTH = 28              // room for most cast friendly names
[<Literal>]
let MODEL_COLUMN_WIDTH = 24             // room for most cast model names
[<Literal>]
let MARKER_SELECTED = "> "              // drawn in front of the highlighted row
[<Literal>]
let MARKER_UNSELECTED = "  "            // same width as the selected marker, keeps columns aligned
[<Literal>]
let MARK_PASS = "✓"                     // shown beside the IP when the ping answered
[<Literal>]
let MARK_FAIL = "✗"                     // shown beside the IP when the ping failed
[<Literal>]
let PROMPT = @":\> "                    // prompt while no device is selected
[<Literal>]
let DEVICE_PROMPT_USER = "root@"        // user part of the prompt once a device is selected
[<Literal>]
let DEVICE_PROMPT_TAIL = ":~# "         // root shell style ending after the device name
[<Literal>]
let MENU_DISCOVER = 0                   // start menu index of Discover devices, Root device is 1
[<Literal>]
let ROOT_LIST_APPS = 0                 // Root device submenu index of List Apps, Back is last
[<Literal>]
let EXIT_OK = 0                        // normal exit, with or without a selection
[<Literal>]
let EXIT_NO_ADAPTER = 1                 // exit code when no usable adapter is found

let HIGHLIGHT_BACKGROUND = ConsoleColor.DarkCyan  // selected row background
let HIGHLIGHT_FOREGROUND = ConsoleColor.White     // selected row text
let PASS_COLOR = ConsoleColor.Green               // IP and mark when the ping answered
let FAIL_COLOR = ConsoleColor.Red                 // IP and mark when the ping failed
let WARNING_COLOR = ConsoleColor.Yellow           // VPN disclaimer text
let DISABLED_COLOR = ConsoleColor.DarkGray        // menu items not available yet
let VPN_WARNING = "You are connected to a VPN. It may cause connection issues. Consider disconnecting"  // shown above the list when a VPN is up
let BANNER = "H.L, LionsHead Analytics Group, https://lionsheadanalyticsgroup.com/"  // boot mark

// lays out the 4 columns after the IP
let formatTail (mac: string) (name: string) (model: string) (port: string) =
    mac.PadRight MAC_COLUMN_WIDTH + name.PadRight NAME_COLUMN_WIDTH + model.PadRight MODEL_COLUMN_WIDTH + port

// lays out the 5 columns of a row without the marker
let formatColumns (ip: string) (mac: string) (name: string) (model: string) (port: string) =
    ip.PadRight IP_COLUMN_WIDTH + formatTail mac name model port

// the announced port as text, empty when the device did not announce one
let portText (device: Device) =
    device.Port |> Option.map string |> Option.defaultValue ""

// formats 1 device as a row
let formatRow (device: Device) =
    formatColumns (device.IP.ToString()) device.MAC device.FriendlyName device.Model (portText device)

(* cuts a line to 1 short of the console width.
   Every list and menu works out screen lines as CursorTop minus the rows printed, which only
   holds if each row takes exactly 1 line. A row that wraps, or exactly fills the width and
   pushes the cursor down, throws every later line off. The VS Code terminal can report a
   narrower width than the panel shows, so this is the width that counts. *)
let fitLine (text: string) =
    let limit = Console.WindowWidth - 1  // last safe column count
    if text.Length > limit then text.Substring(0, max 0 limit) else text

// draws 1 row in place at its screen line, with the marker and colors when selected
let drawRow (top: int) (index: int) (selected: bool) (device: Device) =
    Console.SetCursorPosition(0, top + index)
    if selected then
        Console.BackgroundColor <- HIGHLIGHT_BACKGROUND
        Console.ForegroundColor <- HIGHLIGHT_FOREGROUND
    Console.Write(fitLine ((if selected then MARKER_SELECTED else MARKER_UNSELECTED) + formatRow device))
    Console.ResetColor()

(* redraws the selected row with its IP and mark colored by the ping result.
   The mark sits inside the IP column's padding, so the other columns do not shift,
   and the row is drawn without the highlight background so green and red stay readable. *)
let drawPingResult (line: int) (device: Device) (answered: bool) =
    let ipCell = (device.IP.ToString() + " " + (if answered then MARK_PASS else MARK_FAIL)).PadRight IP_COLUMN_WIDTH
    Console.SetCursorPosition(0, line)
    Console.Write MARKER_SELECTED
    Console.ForegroundColor <- if answered then PASS_COLOR else FAIL_COLOR
    Console.Write ipCell
    Console.ResetColor()
    let tail = formatTail device.MAC device.FriendlyName device.Model (portText device)
    let room = max 0 (Console.WindowWidth - 1 - MARKER_SELECTED.Length - ipCell.Length)  // columns left
    Console.Write(if tail.Length > room then tail.Substring(0, room) else tail)

(* runs the arrow key loop and returns the chosen row's screen line and device, or None on Esc or q.
   The rows are printed once with WriteLine first so the console scrolls to fit them,
   and top is worked out after that. Drawing with SetCursorPosition before the rows
   exist would throw when the list runs past the bottom of the buffer.
   Each key press redraws only the 2 rows that changed, so the list does not flicker. *)
let selectDevice (devices: Device list) =
    let rows = List.toArray devices     // indexed access for the selection
    for device in rows do
        Console.WriteLine(fitLine (MARKER_UNSELECTED + formatRow device))
    let top = Console.CursorTop - rows.Length  // screen line of the first row
    drawRow top 0 true rows.[0]
    let move fromIndex toIndex =
        drawRow top fromIndex false rows.[fromIndex]
        drawRow top toIndex true rows.[toIndex]
        toIndex
    let rec loop selected =
        match (Console.ReadKey true).Key with
        | ConsoleKey.UpArrow when selected > 0 -> loop (move selected (selected - 1))
        | ConsoleKey.DownArrow when selected < rows.Length - 1 -> loop (move selected (selected + 1))
        | ConsoleKey.Enter -> Some (top + selected, rows.[selected])
        | ConsoleKey.Escape | ConsoleKey.Q -> None
        | _ -> loop selected
    Console.CursorVisible <- false
    try
        loop 0
    finally
        Console.SetCursorPosition(0, top + rows.Length)
        Console.CursorVisible <- true

// 1 start menu entry
type MenuItem =
    { Label: string                     // text shown in the menu
      Enabled: bool }                   // false draws it grey and the arrows skip it

// builds the prompt, root@name:~# with a selected device, its IP when it has no mDNS name, :\> before that
let promptFor (selected: Device option) =
    match selected with
    | None -> PROMPT
    | Some device ->
        let host = if String.IsNullOrEmpty device.FriendlyName then device.IP.ToString() else device.FriendlyName
        DEVICE_PROMPT_USER + host + DEVICE_PROMPT_TAIL

// draws 1 menu item in place, grey when disabled, highlighted when selected
let drawMenuItem (top: int) (index: int) (selected: bool) (item: MenuItem) =
    Console.SetCursorPosition(0, top + index)
    if not item.Enabled then
        Console.ForegroundColor <- DISABLED_COLOR
    elif selected then
        Console.BackgroundColor <- HIGHLIGHT_BACKGROUND
        Console.ForegroundColor <- HIGHLIGHT_FOREGROUND
    Console.Write((if selected then MARKER_SELECTED else MARKER_UNSELECTED) + item.Label)
    Console.ResetColor()

(* reserves 1 blank line per item and returns the screen line of the first.
   WriteLine first so the console scrolls to fit, same reason as selectDevice. *)
let reserveLines (count: int) =
    for _ in 1 .. count do
        Console.WriteLine()
    Console.CursorTop - count

(* draws the items from top and runs the arrow key loop, returning the picked index or None on Esc or q.
   Disabled items are skipped. Assumes at least 1 item is enabled. *)
let runPicker (top: int) (rows: MenuItem[]) =
    let firstEnabled = rows |> Array.findIndex (fun item -> item.Enabled)  // starting highlight
    rows |> Array.iteri (fun index item -> drawMenuItem top index (index = firstEnabled) item)
    let nextEnabled fromIndex step =
        let rec find candidate =
            if candidate < 0 || candidate >= rows.Length then fromIndex
            elif rows.[candidate].Enabled then candidate
            else find (candidate + step)
        find (fromIndex + step)
    let move fromIndex toIndex =
        if fromIndex <> toIndex then
            drawMenuItem top fromIndex false rows.[fromIndex]
            drawMenuItem top toIndex true rows.[toIndex]
        toIndex
    let rec loop selected =
        match (Console.ReadKey true).Key with
        | ConsoleKey.UpArrow -> loop (move selected (nextEnabled selected -1))
        | ConsoleKey.DownArrow -> loop (move selected (nextEnabled selected 1))
        | ConsoleKey.Enter -> Some selected
        | ConsoleKey.Escape | ConsoleKey.Q -> None
        | _ -> loop selected
    loop firstEnabled

(* runs the start menu and returns the picked index, or None on Esc or q.
   The prompt prints under the menu, and the cursor is left at its end so callers
   know the prompt's line from Console.CursorTop. *)
let selectMenuItem (items: MenuItem list) (prompt: string) =
    let rows = List.toArray items       // indexed access for the selection
    let top = reserveLines rows.Length  // screen line of the first item
    Console.WriteLine()
    Console.Write prompt
    let promptLine = Console.CursorTop  // screen line the prompt sits on
    Console.CursorVisible <- false
    try
        runPicker top rows
    finally
        Console.SetCursorPosition(prompt.Length, promptLine)
        Console.CursorVisible <- true

(* scans, lists, and pings the picked device, then goes straight back to the menu with no wait.
   Returns the picked device, or None when the list was left with Esc or q or came back empty. *)
let discover (local: Net.NetworkInformation.UnicastIPAddressInformation) =
    Console.Clear()
    printfn "%s" BANNER
    let devices = scan local            // blocks for the ping sweep and mDNS window
    if isVPNConnected () then
        Console.ForegroundColor <- WARNING_COLOR
        printfn "%s" VPN_WARNING
        Console.ResetColor()
    printfn "%s" (fitLine (MARKER_UNSELECTED + formatColumns "IP" "MAC" "Friendly name" "Model" "Port"))
    if devices.IsEmpty then
        Console.Write PROMPT
        Console.ReadLine() |> ignore
        None
    else
        match selectDevice devices with
        | None -> None
        | Some (line, device) ->
            let listEnd = Console.CursorTop  // selectDevice leaves the cursor under the list
            drawPingResult line device (pingOnce device.IP)
            Console.SetCursorPosition(0, listEnd)
            Some device

(* the Root device submenu. Back is always the last item, and Esc or q also go back.
   Any other pick redraws the submenu, so it only returns on Back. *)
let rec rootMenu (prompt: string) =
    Console.Clear()
    printfn "%s" BANNER
    let items =                         // root actions get inserted before Back
        [ { Label = "List Apps"; Enabled = true }
          { Label = "Back"; Enabled = true } ]
    match selectMenuItem items prompt with
    | Some ROOT_LIST_APPS ->
        // TODO List Apps action, not defined yet
        rootMenu prompt
    | _ -> ()

(* the start menu loop. Each pass clears the screen and redraws the banner, menu and prompt,
   then acts on the pick. *)
let rec menuLoop local (selected: Device option) =
    Console.Clear()
    printfn "%s" BANNER
    let items =
        [ { Label = "Discover devices"; Enabled = true }
          { Label = "Root device"; Enabled = selected.IsSome } ]
    match selectMenuItem items (promptFor selected) with
    | None -> EXIT_OK
    | Some MENU_DISCOVER ->
        menuLoop local (discover local |> Option.orElse selected)
    | Some _ ->
        rootMenu (promptFor selected)   // Root device, returns when Back is picked
        menuLoop local selected

[<EntryPoint>]
let main _ =
    Console.OutputEncoding <- Text.Encoding.UTF8  // the console needs UTF8 to draw ✓ and ✗
    printfn "%s" BANNER
    match findLocalIPv4 () with
    | None ->
        eprintfn "TODO copy"
        EXIT_NO_ADAPTER
    | Some local -> menuLoop local None
