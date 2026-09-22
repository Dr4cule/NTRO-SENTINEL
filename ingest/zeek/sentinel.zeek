# Passive Zeek policy. It turns on JSON logs and emits early connection metadata;
# it never opens a connection or reads decrypted TLS/QUIC payloads.
redef LogAscii::use_json = T;
module Sentinel;
export {
 redef enum Log::ID += { LOG };
 type Info: record { ts: time &log; uid: string &log; src_ip: addr &log; src_port: port &log; dst_ip: addr &log; dst_port: port &log; proto: transport_proto &log; };
}
event zeek_init() { Log::create_stream(LOG, Log::Stream($columns=Info, $path="early")); }
event new_connection(c: connection) {
 local rec: Info = [$ts=network_time(), $uid=c$uid, $src_ip=c$id$orig_h, $src_port=c$id$orig_p, $dst_ip=c$id$resp_h, $dst_port=c$id$resp_p, $proto=get_port_transport_proto(c$id$resp_p)];
 Log::write(LOG, rec);
}
