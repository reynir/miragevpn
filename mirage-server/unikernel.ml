open Lwt.Infix

module Main
    (R : Mirage_random.S)
    (M : Mirage_clock.MCLOCK)
    (P : Mirage_clock.PCLOCK)
    (T : Mirage_time.S)
    (S : Tcpip.Stack.V4V6)
    (FS : Mirage_kv.RO) =
struct
  module O = Miragevpn_mirage.Server (R) (M) (P) (T) (S)

  let read_config data =
    FS.get data (Mirage_kv.Key.v "openvpn.config") >|= function
    | Error e -> Error (`Msg (Fmt.to_to_string FS.pp_error e))
    | Ok data ->
        let string_of_file _ = Error (`Msg "no string_of_file support") in
        Miragevpn.Config.parse ~string_of_file data

  let start _ _ _ _ s data =
    read_config data >>= function
    | Error (`Msg msg) ->
        Logs.err (fun m -> m "error while reading config %s" msg);
        failwith "config file error"
    | Ok config ->
        let _t = O.connect config s in
        let task, _u = Lwt.task () in
        task
end
