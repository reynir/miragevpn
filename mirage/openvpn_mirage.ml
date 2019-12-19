(* An OpenVPN layer for MirageOS. Given a stackv4 and a configuration, it
   connects to the OpenVPN gateway in tun mode. Once the tunnel is established,
   an IPv4 stack is returned. *)

(* This effectful OpenVPN client layer is mostly reactive - only when some
   event occured, such as receiving data from the tunnel, a read failure
   (which immediately closes the connection), or a timer `Tick (once every
   second), or an user wants to transmit data (write) over the tunnel, work
   will be done.

   The asynchronous task library Lwt is in use here, which provides cooperative
   tasks -- not preemptive tasks! This means that only at yield points
   (Lwt.bind (>>=) and Lwt.map (>|=)) other tasks can be scheduled. Everything
   between two yield points will happen atomically!

   Speaking of tasks, there are three tasks involved:
   - reader -- which is reading from a given TCP flow (started once
               TCP.create_connection successfully established a connection)
   - timer -- which sleeps for a second, produces a `Tick, in a loop
   - event -- which waits for events (generated by reader and timer), calling
              Openvpn.handle for each event, and executing potential actions
              asynchronously (via Lwt.async handle_action)

   Synchronisation is achieved by Lwt_mvar.t variables, there are two:
   * data_mvar which gets put when payload has been received over the
               tunnel (it is taken by process_data)
   * est_mvar which gets put once the tunnel is established. connect takes
              that before returning (subsequent put mutate t)
   * event_mvar which gets put by timer/reader/handle_action whenever an
                event occured, the event task above waits for it *)

(* TODO to avoid deadlocks, better be sure that
   (a) until connect returns there ain't any data_mvar put happening -- since
       only the task returned by connect (process_data) calls Lwt_mvar.take --
       to-be-called by the client of this stack *)

open Lwt.Infix

let src = Logs.Src.create "openvpn.mirage" ~doc:"OpenVPN MirageOS layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : Mirage_random.S) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (T : Mirage_time.S) (S : Mirage_stack.V4) = struct
  module DNS = Dns_client_mirage.Make(R)(M)(S)
  module TCP = S.TCPV4
  module UDP = S.UDPV4

  type conn = {
    mutable o_client : Openvpn.t ;
    mutable peer : [ `Udp of UDP.t * (int * Ipaddr.V4.t * int) | `Tcp of TCP.flow ] option ;
    data_mvar : Cstruct.t list Lwt_mvar.t ;
    est_mvar : (Openvpn.ip_config * int) Lwt_mvar.t ;
    event_mvar : Openvpn.event Lwt_mvar.t ;
  }

  type t = {
    conn : conn ;
    mutable ip_config : Openvpn.ip_config ;
    mutable mtu : int ;
  }

  let now () = Ptime.v (P.now_d_ps ())

  let get_ip t = t.ip_config.Openvpn.ip

  let mtu t = t.mtu

  let transmit_tcp flow data =
    let ip, port = TCP.dst flow in
    Log.warn (fun m -> m "sending %d bytes to %a:%d"
                 (Cstruct.lenv data) Ipaddr.V4.pp ip port);
    TCP.writev flow data >|= function
    | Ok () -> true
    | Error e ->
      Log.err (fun m -> m "tcp write failed %a" TCP.pp_write_error e);
      false

  let transmit_udp udp (src_port, dst, dst_port) data =
    match data with
    | [] -> Lwt.return true
    | xs ->
      Lwt_list.fold_left_s (fun acc pkt ->
          UDP.write ~src_port ~dst ~dst_port udp pkt >|= function
          | Ok () -> acc
          | Error e ->
            Log.err (fun m -> m "udp write failed %a" UDP.pp_error e); false)
        true xs

  let transmit where data =
    match data, where with
    | [], _ -> Lwt.return true
    | _, Some `Tcp flow -> transmit_tcp flow data
    | _, Some `Udp (udp, peer) -> transmit_udp udp peer data
    | _, None -> Log.err (fun m -> m "transmit, but no peer") ; Lwt.return false

  let write t data =
    match Openvpn.outgoing t.conn.o_client (M.elapsed_ns ()) data with
    | Error `Not_ready ->
      Log.warn (fun m -> m "tunnel not ready, dropping data!");
      Lwt.return false
    | Ok (c', out) ->
      t.conn.o_client <- c';
      transmit t.conn.peer [out]

  let read t = Lwt_mvar.take t.conn.data_mvar

  let resolve_hostname s name =
    let res = DNS.create s in
    DNS.gethostbyname res name >|= function
    | Ok ip -> Some (Ipaddr.V4 ip)
    | Error (`Msg msg) ->
      Log.err (fun m -> m "failed to resolve %a: %s" Domain_name.pp name msg);
      None

  let read_flow flow =
    TCP.read flow >|= fun r ->
    match r with
    | Ok `Data b -> `Data b
    | Ok `Eof -> Log.err (fun m -> m "eof while reading"); `Connection_failed
    | Error e ->
      Log.err (fun m -> m "tcp read error %a" TCP.pp_error e); `Connection_failed

  let rec reader c flow =
    let ip, port = TCP.dst flow in
    Log.info (fun m -> m "reading flow %a:%d" Ipaddr.V4.pp ip port);
    read_flow flow >>= fun r ->
    let n =
      match r with
      | `Connection_failed -> 0
      | `Data r -> Cstruct.len r
      | _ -> assert false
    in
    Log.info (fun m -> m "read flow %a:%d (%d bytes)" Ipaddr.V4.pp ip port n);
    Lwt_mvar.put c r >>= fun () ->
    match r with
    | `Data _ -> reader c flow
    | _ ->
      Log.err (fun m -> m "connection failed, terminating reader");
      Lwt.return_unit

  let udp_read_cb port c (our_port, peer_ip, their_port) ~src ~dst:_ ~src_port data =
    if port = our_port && src_port = their_port && Ipaddr.V4.compare peer_ip src = 0 then begin
      Log.info (fun m -> m "read %a:%d (%d bytes)" Ipaddr.V4.pp src src_port (Cstruct.len data));
      Lwt_mvar.put c (`Data data)
    end else begin
      Log.warn (fun m -> m "ignoring unsolicited data from %a:%d (expected %a:%d, our %d dst %d)"
                   Ipaddr.V4.pp src src_port Ipaddr.V4.pp peer_ip their_port
                   our_port port);
      Lwt.return_unit
    end

  (* TODO the "sw" argument is not used and should be removed! *)
  let connect_tcp sw s (ip, port) =
    TCP.create_connection (S.tcpv4 s) (ip, port) >|= function
    | Ok flow ->
      Log.warn (fun m -> m "connection to %a:%d established"
                   Ipaddr.V4.pp ip port);
      (sw, Some flow)
    | Error tcp_err ->
      Log.err (fun m -> m "failed to connect to %a:%d: %a"
                  Ipaddr.V4.pp ip port TCP.pp_error tcp_err);
      (sw, None)

  (* TODO could be part of type conn above *)
  let conn_est = ref (Lwt_switch.create ())

  let handle_action s conn = function
    | `Resolve (name, _ip_version) ->
      Lwt_switch.turn_off !conn_est >>= fun () ->
      resolve_hostname s name >>= fun r ->
      let ev = match r with None -> `Resolve_failed | Some x -> `Resolved x in
      Lwt_mvar.put conn.event_mvar ev
    | `Connect (Ipaddr.V6 _, _, _) ->
      Log.err (fun m -> m "IPv6 not implemented yet, won't connect");
      Lwt_mvar.put conn.event_mvar `Connection_failed
    | `Connect (Ipaddr.V4 ip, port, `Udp) ->
      (* we don't use the switch, but an earlier connection attempt may have used TCP *)
      Lwt_switch.turn_off !conn_est >>= fun () ->
      conn_est := Lwt_switch.create ();
      (* TODO we may wish to filter certain ports (< 1024) *)
      let our_port = Randomconv.int16 R.generate in
      let peer = our_port, ip, port in
      conn.peer <- Some (`Udp (S.udpv4 s, peer));
      S.listen_udpv4 s ~port:our_port (udp_read_cb our_port conn.event_mvar peer);
      (* TODO for UDP, we atm can't figure out connection failures
         (timeout should work, but ICMP refused/.. won't be delivered here) *)
      Lwt_mvar.put conn.event_mvar `Connected
    | `Connect (Ipaddr.V4 ip, port, `Tcp) ->
      Lwt_switch.turn_off !conn_est >>= fun () ->
      let sw = Lwt_switch.create () in
      conn_est := sw;
      connect_tcp sw s (ip, port) >>= fun (sw', r) ->
      if Lwt_switch.is_on sw' then
        let ev =
          match r with
          | None -> `Connection_failed
          | Some flow ->
            conn.peer <- Some (`Tcp flow);
            Lwt.async (fun () -> reader conn.event_mvar flow);
            (* TODO log on app level *)
            Log.warn (fun m -> m "successfully established connection to %a:%d"
                         Ipaddr.V4.pp ip port);
            `Connected
        in
        Lwt_mvar.put conn.event_mvar ev
      else begin
        Log.warn (fun m -> m "ignoring connection (cancelled by switch)");
        match r with None -> Lwt.return_unit | Some f -> TCP.close f
      end
    | `Disconnect ->
      (* TODO not sure, should maybe signal successful close (to be able to initiate new connection) *)
      begin match conn.peer with
        | None -> Log.err (fun m -> m "cannot disconnect no flow"); Lwt.return_unit
        | Some (`Udp _) ->
          Log.err (fun m -> m "unsure how to disconnect UDP"); Lwt.return_unit
        | Some (`Tcp f) ->
          let ip, port = TCP.dst f in
          Log.err (fun m -> m "disconnecting flow %a:%d" Ipaddr.V4.pp ip port);
          conn.peer <- None ; TCP.close f
      end
    | `Exit -> Lwt.fail_with "exit called"
    | `Payload data -> Lwt_mvar.put conn.data_mvar data
    | `Established (ip, mtu) ->
      Log.warn (fun m -> m "action = established");
      Lwt_mvar.put conn.est_mvar (ip, mtu)

  let rec event s conn =
    Log.info (fun m -> m "processing event");
    Lwt_mvar.take conn.event_mvar >>= fun ev ->
    Log.info (fun m -> m "now for real processing event %a" Openvpn.pp_event ev);
    match Openvpn.handle conn.o_client (now ()) (M.elapsed_ns ()) ev with
    | Error e ->
      Log.err (fun m -> m "openvpn handle failed %a" Openvpn.pp_error e);
      Lwt.return_unit
    | Ok (t', outs, action) ->
      conn.o_client <- t';
      Log.info (fun m -> m "handling action %a" Fmt.(option ~none:(unit "none") Openvpn.pp_action) action);
      (match outs with
       | [] -> ()
       | _ ->
         Lwt.async (fun () ->
             (transmit conn.peer outs >>= function
               | true -> Lwt.return_unit
               | false -> Lwt_mvar.put conn.event_mvar `Connection_failed)));
      (match action with
       | None -> ()
       | Some a -> Lwt.async (fun () -> handle_action s conn a));
      event s conn

  let connect config s =
    match Openvpn.client config (M.elapsed_ns ()) R.generate with
    | Error `Msg msg ->
      Log.err (fun m -> m "client construction failed %s" msg);
      Lwt.return (Error (`Msg msg))
    | Ok (o_client, action) ->
      let data_mvar = Lwt_mvar.create_empty ()
      and est_mvar = Lwt_mvar.create_empty ()
      and event_mvar = Lwt_mvar.create_empty ()
      in
      let conn = { o_client ; peer = None ; data_mvar ; est_mvar ; event_mvar } in
      (* handle initial action *)
      Lwt.async (fun () -> event s conn);
      let rec tick () =
        T.sleep_ns (Duration.of_sec 1) >>= fun () ->
        Lwt_mvar.put event_mvar `Tick >>= fun () ->
        tick ()
      in
      Lwt.async tick;
      Lwt.async (fun () -> handle_action s conn action);
      Log.info (fun m -> m "waiting for established");
      Lwt_mvar.take est_mvar >|= fun (ip_config, mtu) ->
      Log.info (fun m -> m "now established %a (mtu %d)"
                   Openvpn.pp_ip_config ip_config mtu);
      let t = { conn ; ip_config ; mtu } in
      let rec established () =
        (* TODO: signal to upper layer!? *)
        Lwt_mvar.take est_mvar >>= fun (ip_config', mtu') ->
        let ip_changed = Ipaddr.V4.compare ip_config.ip ip_config'.ip <> 0 in
        Log.info (fun m -> m "tunnel re-established (ip changed? %B) %a (mtu %d)"
                     ip_changed Openvpn.pp_ip_config ip_config' mtu');
        if ip_changed then
          t.ip_config <- ip_config';
        (* not sure about mtu changes, but better to update this in any case *)
        t.mtu <- mtu';
        established ()
      in
      Lwt.async established;
      Log.warn (fun m -> m "returning from connect");
      Ok t
end

module Make_stack (R : Mirage_random.S) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (T : Mirage_time.S) (S : Mirage_stack.V4) = struct
  module O = Make(R)(M)(P)(T)(S)

  type t = {
    ovpn : O.t ;
    frags : Fragments.Cache.t ;
  }

  (* boilerplate i don't understand *)
  type ipaddr = Ipaddr.V4.t
  type callback = src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit Lwt.t
  let pp_ipaddr = Ipaddr.V4.pp

  type error = [ Mirage_protocols.Ip.error
               | `Msg of string
               | `Would_fragment
               | `Openvpn of Openvpn.error ]
  let pp_error ppf = function
    | #Mirage_protocols.Ip.error as e -> Mirage_protocols.Ip.pp_error ppf e
    | `Msg m -> Fmt.pf ppf "message %s" m
    | `Openvpn e -> Openvpn.pp_error ppf e

  let disconnect _ =
    Log.warn (fun m -> m "disconnect called, should I do something?");
    Lwt.return_unit

  let get_ip t = O.get_ip t.ovpn

  let mtu t = O.mtu t.ovpn

  let encode hdr data =
    let payload_len = Cstruct.len data
    and hdr_buf = Cstruct.create Ipv4_wire.sizeof_ipv4
    in
    match Ipv4_packet.Marshal.into_cstruct ~payload_len hdr hdr_buf with
    | Error msg ->
      Log.err (fun m -> m "failure while assembling ip frame: %s" msg) ;
      assert false
    | Ok () -> Cstruct.append hdr_buf data

  let write t ?(fragment = true) ?(ttl = 38) ?src dst proto ?(size = 0) headerf bufs =
    (* everything must be unfragmented! the Openvpn.outgoing function prepends *)
    (* whatever we get here we may need to split up *)
    Log.debug (fun m -> m "write size %d bufs len %d" size (Cstruct.lenv bufs));
    (* no options here, always 20 bytes IPv4 header size! *)
    (* first figure out the actual payload a user wants *)
    let u_hdr =
      if size > 0 then
        let b = Cstruct.create size in
        let l = headerf b in
        Cstruct.sub b 0 l
      else
        Cstruct.empty
    in
    let payload = Cstruct.concat (u_hdr :: bufs) in
    let pay_len = Cstruct.len payload in
    let hdr =
      let src = match src with None -> get_ip t | Some x -> x in
      let off = if fragment then 0x0000 else 0x4000 in
      Ipv4_packet.{
        options = Cstruct.empty ;
        src ; dst ;
        ttl ; off ; id = 0 ;
        proto = Ipv4_packet.Marshal.protocol_to_int proto }
    in
    (* now we take chunks of (mtu - hdr_len) one at a time *)
    let mtu = mtu t in
    let ip_payload_len = mtu - Ipv4_wire.sizeof_ipv4 in
    if (not fragment && ip_payload_len < pay_len) || ip_payload_len <= 0 then
      Lwt.return (Error `Would_fragment)
    else
      let outs =
        if pay_len <= ip_payload_len then
          (* simple case, marshal and go ahead *)
          let out = encode hdr payload in
          [ out ]
        else
          (* fragment payload: set ip ID and more_fragments in header *)
          (* need to ensure that our v4 payload is 8byte-bounded *)
          let ip_payload_len' = ip_payload_len - (ip_payload_len mod 8) in
          let hdr = { hdr with id = Randomconv.int16 R.generate ; off = 0x2000 } in
          let pay, rest = Cstruct.split payload ip_payload_len' in
          let first = encode hdr pay in
          let outs = Fragments.fragment ~mtu hdr rest in
          first :: outs
      in
      Lwt_list.fold_left_s (fun acc data ->
          match acc with
          | Error e -> Lwt.return (Error e)
          | Ok () ->
            O.write t.ovpn data >|= fun r ->
            if r then Ok () else Error (`Msg "write failed"))
        (Ok ()) outs

  let input t ~tcp ~udp ~default buf =
    match Ipv4_packet.Unmarshal.of_cstruct buf with
    | Error s ->
      Log.err (fun m -> m "error %s while parsing IPv4 frame %a" s Cstruct.hexdump_pp buf);
      Lwt.return_unit
    | Ok (packet, payload) ->
      Log.info (fun m -> m "received IPv4 frame: %a (payload %d bytes)"
                   Ipv4_packet.pp packet (Cstruct.len payload));
      let r = Fragments.process t.frags (M.elapsed_ns ()) packet payload in
      match r with
      | None -> Lwt.return_unit
      | Some (pkt, payload) ->
        let src, dst = pkt.src, pkt.dst in
        match Ipv4_packet.Unmarshal.int_to_protocol pkt.proto with
        | Some `TCP -> tcp ~src ~dst payload
        | Some `UDP -> udp ~src ~dst payload
        | Some `ICMP | None -> default ~proto:pkt.proto ~src ~dst payload

  let rec process_data ~tcp ~udp ~default t =
    Log.info (fun m -> m "processing data");
    O.read t.ovpn >>= fun datas ->
    Log.info (fun m -> m "now for real processing data (%d, lenv %d)"
                 (List.length datas) (Cstruct.lenv datas));
    Lwt_list.iter_s (input t ~tcp ~udp ~default) datas >>= fun () ->
    process_data ~tcp ~udp ~default t

  let connect cfg s =
    O.connect cfg s >|= function
    | Error e -> Error e
    | Ok ovpn ->
      let frags = Fragments.Cache.create (1024 * 256) in
      Ok ({ ovpn ; frags }, process_data)

  let pseudoheader t ?src dst proto len =
    let src = match src with
      | Some x -> x
      | None -> get_ip t
    in
    Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto len

  let src t ~dst:_ = get_ip t

  let get_ip t = [ get_ip t ]

end
