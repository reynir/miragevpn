open Lwt.Syntax

type established = {
  ip_config : Miragevpn.ip_config;
  mtu : int;
  ping : [ `Ping ] Lwt.t;
  seq_no : int;
}

let safe_close fd =
  Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)

let ticker () =
  let+ () = Lwt_unix.sleep 1. in
  `Tick

let pinger () =
  let+ () = Lwt_unix.sleep 1. in
  `Ping

let resolve (name, ip_version) =
  let res = Dns_client_lwt.create () in
  match ip_version with
  | `Ipv4 | `Any -> (
      let+ r = Dns_client_lwt.gethostbyname res name in
      match r with
      | Error (`Msg x) ->
          Logs.warn (fun m ->
              m "gethostbyname for %a return an error: %s" Domain_name.pp name x);
          `Resolve_failed
      | Ok ip -> `Resolved (Ipaddr.V4 ip))
  | `Ipv6 -> (
      let+ r = Dns_client_lwt.gethostbyname6 res name in
      match r with
      | Error (`Msg x) ->
          Logs.warn (fun m ->
              m "gethostbyname for %a return an error: %s" Domain_name.pp name x);
          `Resolve_failed
      | Ok ip -> `Resolved (Ipaddr.V6 ip))

let pp_action ppf = function
  | #Miragevpn.action as action -> Miragevpn.pp_action ppf action

let event k (tick : [ `Tick ] Lwt.t) client ev =
  Logs.debug (fun m -> m "event %a" Miragevpn.pp_event ev);
  let tick = match ev with `Tick -> ticker () | _ -> tick in
  match Miragevpn.handle client ev with
  | Error e ->
      Logs.err (fun m -> m "miragevpn handle failed %a" Miragevpn.pp_error e);
      exit 4
  | Ok (client, outs, payloads, new_action) ->
      k tick client outs payloads new_action

let mk_ifconfig (ip_config, mtu) =
  { ip_config; mtu; ping = pinger (); seq_no = 0 }

let ping_payload =
  Cstruct.of_string "never gonna give you up\nnever gonna let you down\nlalala!"

let ping ({ ip_config; seq_no; mtu = _; ping = _ } as ifconfig) =
  let ping =
    {
      Icmpv4_packet.code = 0;
      ty = Icmpv4_wire.Echo_request;
      subheader = Icmpv4_packet.Id_and_seq (1024, seq_no);
    }
  in
  let ifconfig = { ifconfig with seq_no = succ seq_no } in
  let payload = ping_payload in
  let icmpv4_hdr = Icmpv4_packet.Marshal.make_cstruct ~payload ping in
  let ipv4_hdr =
    let src = Ipaddr.V4.Prefix.address ip_config.cidr in
    let dst = ip_config.gateway in
    let off = 0x4000 in
    {
      Ipv4_packet.src;
      dst;
      id = 0;
      off;
      ttl = 38;
      proto = Ipv4_packet.Marshal.protocol_to_int `ICMP;
      options = Cstruct.empty;
    }
  in
  let ipv4_hdr =
    Ipv4_packet.Marshal.make_cstruct
      ~payload_len:(Cstruct.lenv [ icmpv4_hdr; payload ])
      ipv4_hdr
  in
  (ifconfig, Cstruct.concat [ ipv4_hdr; icmpv4_hdr; payload ])

let pong { ip_config; _ } buf =
  let ( let* ) = Result.bind and ( let+ ) = Fun.flip Result.map in
  let* ipv4_hdr, off = Ipv4_packet.Unmarshal.header_of_cstruct buf in
  let buf = Cstruct.shift buf off in
  let* () =
    if
      Ipaddr.V4.compare ipv4_hdr.dst (Ipaddr.V4.Prefix.address ip_config.cidr)
      = 0
    then Ok ()
    else
      Fmt.kstr Result.error "Unknown IPv4 recipient %a" Ipaddr.V4.pp
        ipv4_hdr.dst
  in
  let* protocol =
    Ipv4_packet.Unmarshal.int_to_protocol ipv4_hdr.proto
    |> Option.to_result ~none:"Unknown ipv4 protocol"
  in
  let* () =
    match protocol with `ICMP -> Ok () | _ -> Error "Non-ICMP IPv4 packet"
  in
  let* icmpv4_hdr, buf = Icmpv4_packet.Unmarshal.of_cstruct buf in
  let* () =
    match icmpv4_hdr.ty with
    | Icmpv4_wire.Echo_reply -> Ok ()
    | ty ->
        Fmt.kstr Result.error "ICMP type %a"
          (Fmt.of_to_string Icmpv4_wire.ty_to_string)
          ty
  in
  let* () =
    if icmpv4_hdr.code = 0 then Ok ()
    else Fmt.kstr Result.error "ICMP code %d" icmpv4_hdr.code
  in
  let+ id, seq_no =
    match icmpv4_hdr.subheader with
    | Id_and_seq (id, seq_no) -> Ok (id, seq_no)
    | _ ->
        Fmt.kstr Result.error "Unexpected ICMPv4 subheader %a" Icmpv4_packet.pp
          icmpv4_hdr
  in
  Logs.debug (fun m ->
      m "Received ICMPv4 payload %d bytes" (Cstruct.length buf));
  (id, seq_no)

let rec write_to_fd fd data =
  if Cstruct.length data = 0 then Lwt_result.return ()
  else
    Lwt.catch
      (fun () ->
        let* len = Lwt_cstruct.write fd data in
        write_to_fd fd (Cstruct.shift data len))
      (fun e ->
        let+ () = safe_close fd in
        Error (`Msg (Fmt.str "TCP write error %a" Fmt.exn e)))

let receive _proto fd =
  let buf = Cstruct.create_unsafe 65535 in
  let* r = Lwt_result.catch (fun () -> Lwt_cstruct.recvfrom fd buf []) in
  match r with
  | Ok (len, _) ->
      Logs.debug (fun m -> m "received %d bytes" len);
      Lwt.return (`Data (Cstruct.sub buf 0 len))
  | Error exn ->
      let* () = safe_close fd in
      (* XXX: emit `Connection_failed?! *)
      Logs.err (fun m -> m "Receive error %a" Fmt.exn exn);
      exit 3

let transmit proto fd data =
  match proto with
  | `Tcp -> write_to_fd fd data
  | `Udp -> (
      let* r = Lwt_result.catch (fun () -> Lwt_cstruct.write fd data) in
      match r with
      | Ok len when Cstruct.length data <> len ->
          Lwt_result.fail (`Msg "wrote short UDP packet")
      | Ok _ -> Lwt_result.return ()
      | Error exn ->
          let+ () = safe_close fd in
          Error (`Msg (Fmt.str "UDP write error %a" Fmt.exn exn)))

let send_recv proto fd =
  (* 16 is arbitrarily chosen *)
  let max_send = 16 in
  let send_queue = Queue.create () in
  let send_condition = Lwt_condition.create () in
  let recv_mvar = Lwt_mvar.create_empty () in
  let clear_send_queue send_queue =
      let unsent = Queue.length send_queue in
      if unsent > 0 then
        Logs.warn (fun m -> m "Dropping %d unsent packets" unsent);
      Queue.clear send_queue
  in
  let fd' =
    object(_)
      method send data =
        if Queue.length send_queue >= max_send then
          Logs.info (fun m -> m "dropping packet")
        else
          (Queue.add (`Transmit data) send_queue;
           Lwt_condition.signal send_condition ())
      method recv =
        Lwt_mvar.take recv_mvar
      method close =
        clear_send_queue send_queue;
        Queue.add `Stop send_queue;
        Lwt_condition.signal send_condition ();
        safe_close fd
    end
  in
  let rec transmitter () =
    let* ev =
      let* () =
        if Queue.is_empty send_queue then
          Lwt_condition.wait send_condition
        else
          Lwt.return_unit
      in
      match Queue.take send_queue with
      | `Stop -> Lwt.return `Stop
      | `Transmit data ->
        Logs.debug (fun m -> m "Sending one packet of %d" (Queue.length send_queue + 1));
        Lwt.catch
          (fun () ->
             let* r = transmit proto fd data in
             match r with
             | Ok () -> Lwt.return `Continue
             | Error `Msg e ->
               Logs.warn (fun m -> m "Error transmitting packet: %s" e);
               Lwt.return `Close)
          (function
            | Lwt_stream.Empty ->
              Lwt.return `Close
            | e -> Lwt.reraise e)
    in
    match ev with
    | `Continue -> transmitter ()
    | `Stop -> Lwt.return_unit
    | `Close ->
      clear_send_queue send_queue;
      fd'#close
  in
  let rec receiver () =
    let buf = Cstruct.create_unsafe 65535 in
    let* r = Lwt_result.catch (fun () -> Lwt_cstruct.recvfrom fd buf []) in
    match r with
    | Ok (len, _) ->
      Logs.debug (fun m -> m "received %d bytes" len);
      let* () = Lwt_mvar.put recv_mvar (`Data (Cstruct.sub buf 0 len)) in
      receiver ()
    | Error exn ->
      let* () = fd'#close in
      (* XXX: emit `Connection_failed?! *)
      Logs.err (fun m -> m "Receive error %a" Fmt.exn exn);
      Lwt_mvar.put recv_mvar `Connection_failed
  in
  Lwt.async transmitter;
  Lwt.async receiver;
  fd'

let rec established_action proto fd incoming ifconfig tick client outs pkts action =
  Logs.debug (fun m -> m "established_action %a" Fmt.(option ~none:(any "suspend") pp_action) action);
  List.iter (fun data -> fd#send data) outs;
  let* () = Lwt.pause () in
  List.iter (fun data ->
      match pong ifconfig data with
      | Ok (_id, seq_no) ->
          Logs.app (fun m -> m "Received pong icmp_seq=%d" seq_no)
      | Error msg -> Logs.app (fun m -> m "Received unexpected data: %s" msg))
    pkts;
  match action with
  | None -> (
      let* ev =
        Lwt.choose
          [
            (tick :> [ Miragevpn.event | `Ping ] Lwt.t);
            (ifconfig.ping :> [ Miragevpn.event | `Ping ] Lwt.t);
            (incoming :> [ Miragevpn.event | `Ping ] Lwt.t);
          ]
      in
      match ev with
      | `Data _ as ev ->
          let incoming = fd#recv in
          event
            (established_action proto fd incoming ifconfig)
            tick client ev
      | #Miragevpn.event as ev ->
          event
            (established_action proto fd incoming ifconfig)
            tick client ev
      | `Ping -> (
          Logs.app (fun m -> m "Sending ping icmp_seq=%d..." ifconfig.seq_no);
          let ifconfig = { ifconfig with ping = pinger () } in
          let ifconfig, data = ping ifconfig in
          match Miragevpn.outgoing client data with
          | Ok (client, data) ->
              established_action proto fd incoming ifconfig tick client
                [data] [] None
          | Error `Not_ready ->
              Logs.warn (fun m ->
                  m
                    "Trying to ping when miragevpn state machine is not ready; \
                     this should never happen");
              established_action proto fd incoming ifconfig tick client [] [] None)
      )
  | Some `Exit -> Lwt_result.fail (`Msg "Exiting due to Miragevpn engine exit")
  | Some (`Established _ as action) ->
      Logs.err (fun m -> m "Unexpected action %a" pp_action action);
      assert false
  | Some (`Connect _ | `Resolve _) as action ->
      let* () = fd#close in
      connecting_action tick client [] [] action

and connected_action proto fd incoming tick client outs pkts action =
  Logs.debug (fun m -> m "connected_action %a" Fmt.(option ~none:(any "suspend") pp_action) action);
  (match pkts with
   | [] -> ()
   | _ ->
     Logs.warn (fun m -> m "Dropping %d unexpected received tunnel packets" (List.length pkts)));
  List.iter (fun data -> fd#send data) outs;
  let* () = Lwt.pause () in
  match action with
  | None ->
      let* ev =
        Lwt.choose [ (tick :> [ `Tick | `Data of Cstruct.t | `Connection_failed ] Lwt.t); incoming ]
      in
      let incoming =
        match ev with `Data _ -> fd#recv | _ -> incoming
      in
      event
        (connected_action proto fd incoming)
        tick client (ev :> Miragevpn.event)
  | Some `Established ifconfig ->
      Logs.info (fun m ->
          m "Connection established! %a" Miragevpn.pp_ip_config (fst ifconfig));
      let ifconfig = mk_ifconfig ifconfig in
      established_action proto fd incoming ifconfig tick client [] [] None
  | Some `Exit -> Lwt_result.fail (`Msg "Exiting due to Miragevpn engine exit")
  | Some (`Connect _ | `Resolve _) as action ->
      let* () = fd#close in
      connecting_action tick client [] [] action

and connecting_action tick client outs pkts action =
  Logs.debug (fun m -> m "connecting_action %a" Fmt.(option ~none:(any "suspend") pp_action) action);
  (match pkts with
   | [] -> ()
   | _ ->
     Logs.warn (fun m -> m "Dropping %d unexpected received tunnel packets" (List.length pkts)));
  (match outs with
   | [] -> ()
   | _ ->
     Logs.warn (fun m -> m "Dropping %d unexpected outgoing packets" (List.length outs)));
  match action with
  | None ->
      let* `Tick = tick in
      event connecting_action tick client `Tick
  | Some `Resolve data ->
      let* ev = resolve data in
      event connecting_action tick client ev
  | Some `Connect (addr, port, proto) ->
      let dom =
        Ipaddr.(Lwt_unix.(match addr with V4 _ -> PF_INET | V6 _ -> PF_INET6))
      and unix_ip = Ipaddr_unix.to_inet_addr addr in
      let sock_typ =
        match proto with `Tcp -> Unix.SOCK_STREAM | `Udp -> Unix.SOCK_DGRAM
      in
      let fd = Lwt_unix.socket dom sock_typ 0 in
      let connect =
        Lwt.catch
          (fun () ->
            let+ () = Lwt_unix.connect fd (ADDR_INET (unix_ip, port)) in
            Logs.app (fun m -> m "Connected to %a:%d" Ipaddr.pp addr port);
            let fd = send_recv proto fd in
            let incoming = fd#recv in
            (`Connected, connected_action proto fd incoming))
          (fun e ->
            Logs.err (fun m ->
                m "error %s while connecting to %a:%d" (Printexc.to_string e)
                  Ipaddr.pp addr port);
            let+ () = safe_close fd in
            (`Connection_failed, connecting_action))
      in
      let* ev, k = connect in
      event k tick client ev
  | Some `Exit -> Lwt_result.fail (`Msg "Exiting due to Miragevpn engine exit")
  | Some (`Established _ as action) ->
      Logs.err (fun m -> m "Unexpected action %a" pp_action action);
      assert false

let establish_tunnel config pkcs12_password =
  let ts () = Mtime.Span.to_uint64_ns (Mtime_clock.elapsed ())
  and now = Ptime_clock.now
  and rng = Mirage_crypto_rng.generate in
  match Miragevpn.client ?pkcs12_password config ts now rng with
  | Error (`Msg msg) ->
      Logs.err (fun m -> m "client construction failed: %s" msg);
      exit 3
  | Ok (client, action) ->
      let tick =
        let+ () = Lwt_unix.sleep 1. in
        `Tick
      in
      connecting_action tick client [] [] (Some (action :> Miragevpn.action))

let string_of_file ~dir filename =
  let file =
    if Filename.is_relative filename then Filename.concat dir filename
    else filename
  in
  try
    let fh = open_in file in
    let content = really_input_string fh (in_channel_length fh) in
    close_in_noerr fh;
    Ok content
  with _ ->
    Fmt.kstr (fun msg -> Error (`Msg msg)) "Error reading file %S" file

let parse_config filename =
  Lwt.return
  @@
  let dir, filename = Filename.(dirname filename, basename filename) in
  let string_of_file = string_of_file ~dir in
  match string_of_file filename with
  | Ok str -> Miragevpn.Config.parse_client ~string_of_file str
  | Error _ as e -> e

let jump _ filename pkcs12 =
  Mirage_crypto_rng_lwt.initialize (module Mirage_crypto_rng.Fortuna);
  Lwt_main.run
    (let* config = parse_config filename in
     match config with
     | Error (`Msg s) -> failwith ("config parser: " ^ s)
     | Ok config -> establish_tunnel config pkcs12)

let reporter_with_ts ~dst () =
  let pp_tags f tags =
    let pp tag () =
      let (Logs.Tag.V (def, value)) = tag in
      Format.fprintf f " %s=%a" (Logs.Tag.name def) (Logs.Tag.printer def) value;
      ()
    in
    Logs.Tag.fold pp tags ()
  in
  let report src level ~over k msgf =
    let tz_offset_s = Ptime_clock.current_tz_offset_s () in
    let posix_time = Ptime_clock.now () in
    let src = Logs.Src.name src in
    let k _ =
      over ();
      k ()
    in
    msgf @@ fun ?header ?tags fmt ->
    Format.kfprintf k dst
      ("%a:%a %a [%s] @[" ^^ fmt ^^ "@]@.")
      (Ptime.pp_rfc3339 ?tz_offset_s ())
      posix_time
      Fmt.(option ~none:(any "") pp_tags)
      tags Logs_fmt.pp_header (level, header) src
  in
  { Logs.report }

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (reporter_with_ts ~dst:Format.std_formatter ())

open Cmdliner

let setup_log =
  Term.(const setup_log $ Fmt_cli.style_renderer () $ Logs_cli.level ())

let config =
  let doc = "Configuration file to use" in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"CONFIG")

let pkcs12 =
  let doc = "PKCS12 password" in
  Arg.(
    value
    & opt (some string) None
    & info [ "pkcs12-password" ] ~doc ~docv:"PKCS12-PASSWORD")

let cmd =
  let term = Term.(term_result (const jump $ setup_log $ config $ pkcs12))
  and info = Cmd.info "miragevpn_client" ~version:"%%VERSION_NUM%%" in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
