open Mirage

let data_key = Key.(value @@ kv_ro ~group:"data" ())
let data = generic_kv_ro ~key:data_key "config"

let private_netif = netif ~group:"private" "private"
let private_ethernet = etif private_netif
let private_arp = arp private_ethernet
let private_ipv4 = create_ipv4 ~group:"private" private_ethernet private_arp

let openvpn_handler =
  let packages =
    let pin = "https://git.robur.io/openvpn.git"
    and udns = "https://github.com/roburio/udns.git"
    in
    [
      package "logs" ;
      package ~pin ~sublibs:["mirage"] "openvpn";
      package ~pin:udns "dns";
      package ~pin:udns "dns-client";
      package ~pin:udns "dns-mirage-client";
      package "mirage-kv";
      package "mirage-nat"
    ]
  in
  foreign
    ~deps:[abstract nocrypto]
    ~packages
    "Unikernel.Main"
    (random @-> mclock @-> pclock @-> time @-> stackv4 @-> network @-> ethernet @-> arpv4 @-> ipv4 @-> kv_ro @-> job)

let () =
  register "client" [openvpn_handler $ default_random $ default_monotonic_clock $ default_posix_clock $ default_time $ generic_stackv4 default_network $ private_netif $ private_ethernet $ private_arp $ private_ipv4 $ data ]