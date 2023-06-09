#ifndef _ND_TLS_ALPN
#define _ND_TLS_ALPN

// Update with ./util/generate-tls-alpn.sh

#define ND_TLS_ALPN_MAX 19

struct nd_alpn_entry {
    const char alpn[ND_TLS_ALPN_MAX];
    nd_proto_id_t proto_id;
};

const struct nd_alpn_entry nd_alpn_proto_map[] = {
    { { 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39 /* http/0.9 */, 0x00 }, ND_PROTO_HTTPS },
    { { 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30 /* http/1.0 */, 0x00 }, ND_PROTO_HTTPS },
    { { 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31 /* http/1.1 */, 0x00 }, ND_PROTO_HTTPS },
    { { 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31 /* spdy/1 */, 0x00 }, ND_PROTO_QUIC },
    { { 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32 /* spdy/2 */, 0x00 }, ND_PROTO_QUIC },
    { { 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33 /* spdy/3 */, 0x00 }, ND_PROTO_QUIC },
    { { 0x73, 0x74, 0x75, 0x6E, 0x2E, 0x74, 0x75, 0x72, 0x6E /* stun.turn */, 0x00 }, ND_PROTO_STUN },
    { { 0x73, 0x74, 0x75, 0x6E, 0x2E, 0x6e, 0x61, 0x74, 0x2d, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79 /* stun.nat-discovery */, 0x00 }, ND_PROTO_STUN },
    { { 0x68, 0x32 /* h2 */, 0x00 }, ND_PROTO_HTTPS },
    { { 0x68, 0x32, 0x63 /* h2c */, 0x00 }, ND_PROTO_HTTPS },
    { { 0x77, 0x65, 0x62, 0x72, 0x74, 0x63 /* webrtc */, 0x00 }, ND_PROTO_TLS },
    { { 0x63, 0x2d, 0x77, 0x65, 0x62, 0x72, 0x74, 0x63 /* c-webrtc */, 0x00 }, ND_PROTO_TLS },
    { { 0x66, 0x74, 0x70 /* ftp */, 0x00 }, ND_PROTO_FTP_DATA },
    { { 0x69, 0x6d, 0x61, 0x70 /* imap */, 0x00 }, ND_PROTO_MAIL_IMAPS },
    { { 0x70, 0x6f, 0x70, 0x33 /* pop3 */, 0x00 }, ND_PROTO_MAIL_POPS },
    { { 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x73, 0x69, 0x65, 0x76, 0x65 /* managesieve */, 0x00 }, ND_PROTO_TLS },
    { { 0x63, 0x6f, 0x61, 0x70 /* coap */, 0x00 }, ND_PROTO_COAP },
    { { 0x78, 0x6d, 0x70, 0x70, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74 /* xmpp-client */, 0x00 }, ND_PROTO_TLS },
    { { 0x78, 0x6d, 0x70, 0x70, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 /* xmpp-server */, 0x00 }, ND_PROTO_TLS },
    { { 0x61, 0x63, 0x6d, 0x65, 0x2d, 0x74, 0x6c, 0x73, 0x2f, 0x31 /* acme-tls/1 */, 0x00 }, ND_PROTO_TLS },
    { { 0x6d, 0x71, 0x74, 0x74 /* mqtt */, 0x00 }, ND_PROTO_MQTTS },
    { { 0x64, 0x6F, 0x74 /* dot */, 0x00 }, ND_PROTO_DOH },
    { { 0x64, 0x6F, 0x71 /* doq */, 0x00 }, ND_PROTO_DOQ },
    { { 0x6E, 0x74, 0x73, 0x6B, 0x65, 0x2F, 0x31 /* ntske/1 */, 0x00 }, ND_PROTO_TLS },
    { { 0x73, 0x75, 0x6e, 0x72, 0x70, 0x63 /* sunrpc */, 0x00 }, ND_PROTO_TLS },
    { { 0x68, 0x33 /* h3 */, 0x00 }, ND_PROTO_QUIC },
    { { 0x73, 0x6D, 0x62 /* smb */, 0x00 }, ND_PROTO_SMBV23 },
    { { 0x69, 0x72, 0x63 /* irc */, 0x00 }, ND_PROTO_IRCS },
    { { 0x00 }, ND_PROTO_UNKNOWN }
};

#endif // _ND_TLS_ALPN
