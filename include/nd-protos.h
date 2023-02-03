// Netify Agent
// Copyright (C) 2015-2022 eGloo Incorporated <http://www.egloo.ca>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifndef _ND_PROTOS_H
#define _ND_PROTOS_H

typedef enum {
    ND_PROTO_UNKNOWN                = 0,
    ND_PROTO_FTP_CONTROL            = 1,
    ND_PROTO_MAIL_POP               = 2,
    ND_PROTO_MAIL_SMTP              = 3,
    ND_PROTO_MAIL_IMAP              = 4,
    ND_PROTO_DNS                    = 5,
    ND_PROTO_IPP                    = 6,
    ND_PROTO_HTTP                   = 7,
    ND_PROTO_MDNS                   = 8,
    ND_PROTO_NTP                    = 9,
    ND_PROTO_NETBIOS                = 10,
    ND_PROTO_NFS                    = 11,
    ND_PROTO_SSDP                   = 12,
    ND_PROTO_BGP                    = 13,
    ND_PROTO_SNMP                   = 14,
    ND_PROTO_XDMCP                  = 15,
    ND_PROTO_SMBV1                  = 16,
    ND_PROTO_SYSLOG                 = 17,
    ND_PROTO_DHCP                   = 18,
    ND_PROTO_POSTGRES               = 19,
    ND_PROTO_MYSQL                  = 20,
    ND_PROTO_FTPS                   = 21,
    ND_PROTO_DEPR22                 = 22,   // Deprecated: Direct Download Link
    ND_PROTO_MAIL_POPS              = 23,
    ND_PROTO_DEPR24                 = 24,   // Deprecated: AppleJuice
    ND_PROTO_DEPR25                 = 25,   // Deprecated: DirectConnect
    ND_PROTO_DEPR26                 = 26,   // Deprecated: NTOP
    ND_PROTO_COAP                   = 27,
    ND_PROTO_VMWARE                 = 28,
    ND_PROTO_MAIL_SMTPS             = 29,
    ND_PROTO_DEPR30                 = 30,   // Deprecated: Facebook Zero
    ND_PROTO_UBNTAC2                = 31,
    ND_PROTO_KONTIKI                = 32,
    ND_PROTO_DEPR33                 = 33,   // Deprecated: OpenFT
    ND_PROTO_DEPR34                 = 34,   // Deprecated: FastTrack
    ND_PROTO_GNUTELLA               = 35,
    ND_PROTO_DEPR36                 = 36,   // Deprecated: eDonkey
    ND_PROTO_BITTORRENT             = 37,
    ND_PROTO_SKYPE_TEAMS_CALL       = 38,
    ND_PROTO_SIGNAL_CALL            = 39,
    ND_PROTO_MEMCACHED              = 40,
    ND_PROTO_SMBV23                 = 41,
    ND_PROTO_MINING                 = 42,
    ND_PROTO_NEST_LOG_SINK          = 43,
    ND_PROTO_MODBUS                 = 44,
    ND_PROTO_DEPR45                 = 45,   // Deprecated: WhatsApp Video
    ND_PROTO_DATASAVER              = 46,
    ND_PROTO_XBOX                   = 47,
    ND_PROTO_QQ                     = 48,
    ND_PROTO_TIKTOK                 = 49,
    ND_PROTO_RTSP                   = 50,
    ND_PROTO_MAIL_IMAPS             = 51,
    ND_PROTO_ICECAST                = 52,
    ND_PROTO_DEPR53                 = 53,   // Deprecated: PPLive
    ND_PROTO_PPSTREAM               = 54,
    ND_PROTO_ZATTOO                 = 55,
    ND_PROTO_DEPR56                 = 56,   // Deprecated: Shoutcast
    ND_PROTO_DEPR57                 = 57,   // Deprecated: Sopcast
    ND_PROTO_DEPR58                 = 58,   // Deprecated: TVANTS
    ND_PROTO_TVUPLAYER              = 59,
    ND_PROTO_DEPR60                 = 60,   // Deprecated: HTTP_Download
    ND_PROTO_QQLIVE                 = 61,
    ND_PROTO_DEPR62                 = 62,   // Deprecated: Thunder
    ND_PROTO_DEPR63                 = 63,   // Deprecated: SoulSeek
    ND_PROTO_DEPR64                 = 64,   // Deprecated: SSL No Cert
    ND_PROTO_IRC                    = 65,
    ND_PROTO_DEPR66                 = 66,   // Deprecated: Ayiya
    ND_PROTO_XMPP                   = 67,   // Renamed: Jabber
    ND_PROTO_FREE68                 = 68,
    ND_PROTO_FREE69                 = 69,
    ND_PROTO_DEPR70                 = 70,   // Deprecated: Yahoo
    ND_PROTO_FREE71                 = 71,
    ND_PROTO_FREE72                 = 72,
    ND_PROTO_IP_VRRP                = 73,
    ND_PROTO_STEAM                  = 74,
    ND_PROTO_HALFLIFE2              = 75,
    ND_PROTO_WORLDOFWARCRAFT        = 76,
    ND_PROTO_TELNET                 = 77,
    ND_PROTO_STUN                   = 78,
    ND_PROTO_IPSEC                  = 79,
    ND_PROTO_IP_GRE                 = 80,
    ND_PROTO_IP_ICMP                = 81,
    ND_PROTO_IP_IGMP                = 82,
    ND_PROTO_IP_EGP                 = 83,
    ND_PROTO_IP_SCTP                = 84,
    ND_PROTO_IP_OSPF                = 85,
    ND_PROTO_IP_IP_IN_IP            = 86,
    ND_PROTO_RTP                    = 87,
    ND_PROTO_RDP                    = 88,
    ND_PROTO_VNC                    = 89,
    ND_PROTO_DEPR90                 = 90,   // Deprecated: pcAnywhere
    ND_PROTO_TLS                    = 91,
    ND_PROTO_SSH                    = 92,
    ND_PROTO_NNTP                   = 93,
    ND_PROTO_MGCP                   = 94,
    ND_PROTO_IAX                    = 95,
    ND_PROTO_TFTP                   = 96,
    ND_PROTO_AFP                    = 97,
    ND_PROTO_DEPR98                 = 98,   // Deprecated: StealthNet
    ND_PROTO_DEPR99                 = 99,   // Deprecated: Aimini
    ND_PROTO_SIP                    = 100,
    ND_PROTO_TRUPHONE               = 101,
    ND_PROTO_IP_ICMPV6              = 102,
    ND_PROTO_DHCPV6                 = 103,
    ND_PROTO_ARMAGETRON             = 104,
    ND_PROTO_CROSSFIRE              = 105,
    ND_PROTO_DOFUS                  = 106,
    ND_PROTO_DEPR107                = 107,  // Deprecated: Fiesta
    ND_PROTO_DEPR108                = 108,  // Deprecated: Florensia
    ND_PROTO_GUILDWARS              = 109,
    ND_PROTO_FREE110                = 110,
    ND_PROTO_KERBEROS               = 111,
    ND_PROTO_LDAP                   = 112,
    ND_PROTO_MAPLESTORY             = 113,
    ND_PROTO_MSSQL_TDS              = 114,
    ND_PROTO_PPTP                   = 115,
    ND_PROTO_WARCRAFT3              = 116,
    ND_PROTO_WORLDOFKUNGFU          = 117,
    ND_PROTO_DEPR118                = 118,  // Deprecated: Slack
    ND_PROTO_FREE119                = 119,
    ND_PROTO_FREE120                = 120,
    ND_PROTO_DROPBOX                = 121,
    ND_PROTO_FREE122                = 122,
    ND_PROTO_FREE123                = 123,
    ND_PROTO_FREE124                = 124,
    ND_PROTO_DEPR125                = 125,  // Deprecated: Skype
    ND_PROTO_FREE126                = 126,
    ND_PROTO_RPC                    = 127,  // Renamed: DCERPC -> RPC
    ND_PROTO_NETFLOW                = 128,
    ND_PROTO_SFLOW                  = 129,
    ND_PROTO_HTTP_CONNECT           = 130,
    ND_PROTO_HTTP_PROXY             = 131,
    ND_PROTO_CITRIX                 = 132,
    ND_PROTO_FREE133                = 133,
    ND_PROTO_FREE134                = 134,
    ND_PROTO_DEPR135                = 135,  // Deprecated: Waze
    ND_PROTO_FREE136                = 136,
    ND_PROTO_DEPR137                = 137,  // Deprecated: Generic (old category matching)
    ND_PROTO_CHECKMK                = 138,
    ND_PROTO_AJP                    = 139,
    ND_PROTO_DEPR140                = 140,  // Deprecated: Apple
    ND_PROTO_FREE141                = 141,
    ND_PROTO_WHATSAPP               = 142,
    ND_PROTO_DEPR143                = 143,  // Deprecated: Apple iCloud
    ND_PROTO_VIBER                  = 144,
    ND_PROTO_DEPR145                = 145,  // Deprecated: Apple iTunes
    ND_PROTO_RADIUS                 = 146,
    ND_PROTO_FREE147                = 147,
    ND_PROTO_TEAMVIEWER             = 148,
    ND_PROTO_FREE149                = 149,
    ND_PROTO_LOTUS_NOTES            = 150,
    ND_PROTO_SAP                    = 151,
    ND_PROTO_GTP                    = 152,
    ND_PROTO_WSD                    = 153,  // Renamed: UPnP
    ND_PROTO_LLMNR                  = 154,
    ND_PROTO_REMOTE_SCAN            = 155,
    ND_PROTO_SPOTIFY                = 156,
    ND_PROTO_DEPR157                = 157,  // Deprecated: FB? Messenger
    ND_PROTO_H323                   = 158,
    ND_PROTO_OPENVPN                = 159,
    ND_PROTO_NOE                    = 160,  // Alcatel new office environment
    ND_PROTO_CISCO_VPN              = 161,
    ND_PROTO_TEAMSPEAK              = 162,
    ND_PROTO_DEPR163                = 163,  // Deprecated: TOR
    ND_PROTO_CISCO_SKINNY           = 164,
    ND_PROTO_RTCP                   = 165,
    ND_PROTO_RSYNC                  = 166,
    ND_PROTO_ORACLE                 = 167,
    ND_PROTO_CORBA                  = 168,
    ND_PROTO_FREE169                = 169,
    ND_PROTO_WHOIS_DAS              = 170,
    ND_PROTO_COLLECTD               = 171,
    ND_PROTO_SOCKS                  = 172,
    ND_PROTO_NINTENDO               = 173,
    ND_PROTO_RTMP                   = 174,
    ND_PROTO_FTP_DATA               = 175,
    ND_PROTO_FREE176                = 176,
    ND_PROTO_ZMQ                    = 177,
    ND_PROTO_FREE178                = 178,
    ND_PROTO_FREE179                = 179,
    ND_PROTO_FREE180                = 180,
    ND_PROTO_MEGACO                 = 181,
    ND_PROTO_REDIS                  = 182,
    ND_PROTO_FREE183                = 183,
    ND_PROTO_VHUA                   = 184,
    ND_PROTO_TELEGRAM               = 185,
    ND_PROTO_FREE186                = 186,
    ND_PROTO_FREE187                = 187,
    ND_PROTO_QUIC                   = 188,
    ND_PROTO_DEPR189                = 189,  // Deprecated: WhatsApp/Voice
    ND_PROTO_EAQ                    = 190,
    ND_PROTO_OOKLA                  = 191,
    ND_PROTO_AMQP                   = 192,
    ND_PROTO_DEPR193                = 193,  // Deprecated: Kakaotalk
    ND_PROTO_KAKAOTALK_VOICE        = 194,
    ND_PROTO_FREE195                = 195,
    ND_PROTO_HTTPS                  = 196,
    ND_PROTO_FREE197                = 197,
    ND_PROTO_MPEGTS                 = 198,
    ND_PROTO_FREE199                = 199,
    ND_PROTO_FREE200                = 200,
    ND_PROTO_FREE201                = 201,
    ND_PROTO_FREE202                = 202,
    ND_PROTO_FREE203                = 203,
    ND_PROTO_BJNP                   = 204,
    ND_PROTO_FREE205                = 205,
    ND_PROTO_WIREGUARD              = 206,
    ND_PROTO_SMPP                   = 207,
    ND_PROTO_FREE208                = 208,
    ND_PROTO_TINC                   = 209,
    ND_PROTO_FREE210                = 210,
    ND_PROTO_FREE211                = 211,
    ND_PROTO_FREE212                = 212,
    ND_PROTO_STARCRAFT              = 213,
    ND_PROTO_TEREDO                 = 214,
    ND_PROTO_DEPR215                = 215,  // Deprecated: Hotspot Shield VPN
    ND_PROTO_DEPR216                = 216,  // Deprecated: HEP
    ND_PROTO_FREE217                = 217,
    ND_PROTO_FREE218                = 218,
    ND_PROTO_FREE219                = 219,
    ND_PROTO_FREE220                = 220,
    ND_PROTO_FREE221                = 221,
    ND_PROTO_MQTT                   = 222,
    ND_PROTO_RX                     = 223,
    ND_PROTO_FREE224                = 224,
    ND_PROTO_FREE225                = 225,
    ND_PROTO_GIT                    = 226,
    ND_PROTO_DRDA                   = 227,
    ND_PROTO_FREE228                = 228,
    ND_PROTO_SOMEIP                 = 229,
    ND_PROTO_FIX                    = 230,
    ND_PROTO_FREE231                = 231,
    ND_PROTO_FREE232                = 232,
    ND_PROTO_FREE233                = 233,
    ND_PROTO_FREE234                = 234,
    ND_PROTO_CSGO                   = 235,
    ND_PROTO_LISP                   = 236,
    ND_PROTO_DIAMETER               = 237,
    ND_PROTO_APPLE_PUSH             = 238,
    ND_PROTO_FREE239                = 239,
    ND_PROTO_FREE240                = 240,
    ND_PROTO_FREE241                = 241,
    ND_PROTO_FREE242                = 242,
    ND_PROTO_DOH                    = 243,
    ND_PROTO_DTLS                   = 244,
    ND_PROTO_GOOGLE_MEET_DUO        = 245,  // TODO: Implement in Agent.
    ND_PROTO_WHATSAPP_CALL          = 246,
    ND_PROTO_SKYPE_TEAMS            = 247,  // TODO: Implement in Agent.
    ND_PROTO_ZOOM                   = 248,
    ND_PROTO_FREE249                = 249,
    ND_PROTO_FREE250                = 250,
    ND_PROTO_FREE251                = 251,
    ND_PROTO_FREE252                = 252,
    ND_PROTO_FREE253                = 253,
    ND_PROTO_FREE254                = 254,
    ND_PROTO_SNAPCHAT_CALL          = 255,
    ND_PROTO_FTPS_DATA              = 256,
    ND_PROTO_SIPS                   = 257,
    ND_PROTO_MQTTS                  = 258,
    ND_PROTO_NNTPS                  = 259,
    ND_PROTO_DOT                    = 260,
    ND_PROTO_DOQ                    = 261,  // TODO: Refine QUIC via ALPN (doq)
    ND_PROTO_DEPR262                = 262,  // Deprecated: Amazon Video
    ND_PROTO_AMONG_US               = 263,
    ND_PROTO_AVAST_SDNS             = 264,
    ND_PROTO_CAPWAP                 = 265,
    ND_PROTO_CASSANDRA              = 266,
    ND_PROTO_CPHA                   = 267,
    ND_PROTO_DNP3                   = 268,
    ND_PROTO_DNSCRYPT               = 269,

    // EtherNet/IP (explicit messaging)
    // https://www.odva.org/wp-content/uploads/2021/05/PUB00138R7_Tech-Series-EtherNetIP.pdf
    ND_PROTO_ETHERNET_IP            = 270,

    ND_PROTO_GENSHIN_IMPACT         = 271,
    ND_PROTO_GTP_C                  = 272,
    ND_PROTO_GTP_P                  = 273,
    ND_PROTO_GTP_U                  = 274,
    ND_PROTO_HP_VIRTGRP             = 275,
    ND_PROTO_CISCO_HSRP             = 276,
    ND_PROTO_IEC60870_5_104         = 277,  // Extension for industrial 104 protocol recognition
    ND_PROTO_DEPR278                = 278,  // Deprecated: IMO
    ND_PROTO_IRCS                   = 279,  // IRC over TLS
    ND_PROTO_MONGODB                = 280,  // MongoDB

    // NATS: Connective Technology for Adaptive Edge & Distributed Systems
    // https://docs.nats.io/
    ND_PROTO_NATS                   = 281,

    // S7comm (S7 Communication) is a Siemens proprietary protocol that runs
    // between programmable logic controllers (PLCs) of the Siemens S7-300/400 family.
    ND_PROTO_S7COMM                 = 282,

    ND_PROTO_SOAP                   = 283,
    ND_PROTO_TARGUS_GETDATA         = 284,  // Targus Dataspeed (speedtest).
    ND_PROTO_VXLAN                  = 285,  // Virtual Extensible LAN.
    ND_PROTO_WEBSOCKET              = 286,  // Websocket

    // Z39.50 dissector.
    // International standard client–server, application layer communications protocol.
    ND_PROTO_Z3950                  = 287,

    ND_PROTO_ZABBIX                 = 288,

    ND_PROTO_I3D                    = 289,
    ND_PROTO_MPEGDASH               = 290,
    ND_PROTO_RAKNET                 = 291,
    ND_PROTO_RIOTGAMES              = 292,
    ND_PROTO_RSH                    = 293,
    ND_PROTO_SD_RTN                 = 294,
    ND_PROTO_TOCA_BOCA              = 295,
    ND_PROTO_ULTRASURF              = 296,
    ND_PROTO_XIAOMI                 = 297,
    ND_PROTO_IP_PGM                 = 298,
    ND_PROTO_IP_PIM                 = 299,
    ND_PROTO_THREEMA                = 300,
    ND_PROTO_ALICLOUD               = 301,
    ND_PROTO_SYSLOGS                = 302,
    ND_PROTO_NATPMP                 = 303,  // NAT Port Mapping Protocol
    // TUYA LAN Protocol
    // https://github.com/tuya/tuya-iotos-embeded-sdk-wifi-ble-bk7231n */
    ND_PROTO_TUYA_LP                = 304,

    ND_PROTO_ELASTICSEARCH          = 305,
    ND_PROTO_AVAST                  = 306,
    ND_PROTO_CRYNET                 = 307,
    ND_PROTO_FASTCGI                = 308,
    ND_PROTO_KISMET                 = 309,
    ND_PROTO_LINE_CALL              = 310,
    ND_PROTO_MUNIN                  = 311,
    ND_PROTO_SYNCTHING              = 312,
    ND_PROTO_TIVOCONNECT            = 313,
    ND_PROTO_TPLINK_SHP             = 314,  // TP-LINK Smart Home Protocol
    ND_PROTO_TAILSCALE              = 315,  // Tailscale
    ND_PROTO_MERAKI_CLOUD           = 316,  // Meraki Cloud

    ND_PROTO_MAX,
    ND_PROTO_TODO                   = 0xffffffff
} nd_proto_id_t;

typedef unordered_map<unsigned, const char *> nd_protos_t;

const nd_protos_t nd_protos = {
    { ND_PROTO_AFP, "AFP" },
    { ND_PROTO_AJP, "AJP" },
    { ND_PROTO_ALICLOUD, "Alibaba/Cloud" },
    { ND_PROTO_AMONG_US, "AmongUs" },
    { ND_PROTO_AMQP, "AMQP" },
    { ND_PROTO_APPLE_PUSH, "Apple/Push" },
    { ND_PROTO_ARMAGETRON, "Armagetron" },
    { ND_PROTO_AVAST, "AVAST" },
    { ND_PROTO_AVAST_SDNS, "AVASTSecureDNS" },
    { ND_PROTO_BGP, "BGP" },
    { ND_PROTO_BITTORRENT, "BitTorrent" },
    { ND_PROTO_BJNP, "BJNP" },
    { ND_PROTO_CAPWAP, "CAPWAP" },
    { ND_PROTO_CASSANDRA, "Cassandra" },
    { ND_PROTO_CHECKMK, "CHECKMK" },
    { ND_PROTO_CISCO_HSRP, "Cisco/HSRP" },
    { ND_PROTO_CISCO_SKINNY, "Cisco/Skinny" },
    { ND_PROTO_CISCO_VPN, "Cisco/VPN" },
    { ND_PROTO_CITRIX, "Citrix" },
    { ND_PROTO_COAP, "COAP" },
    { ND_PROTO_COLLECTD, "Collectd" },
    { ND_PROTO_CORBA, "Corba" },
    { ND_PROTO_CPHA, "CheckPointHA" },
    { ND_PROTO_CROSSFIRE, "Crossfire" },
    { ND_PROTO_CRYNET, "CryNetwork" },
    { ND_PROTO_CSGO, "CSGO" },
    { ND_PROTO_DHCP, "DHCP" },
    { ND_PROTO_DHCPV6, "DHCPv6" },
    { ND_PROTO_DIAMETER, "Diameter" },
    { ND_PROTO_DNP3, "DNP3" },
    { ND_PROTO_DNS, "DNS" },
    { ND_PROTO_DNSCRYPT, "DNSCrypt" },
    { ND_PROTO_DOFUS, "Dofus" },
    { ND_PROTO_DOH, "DoH" },
    { ND_PROTO_DOQ, "DoQ" },
    { ND_PROTO_DOT, "DoT" },
    { ND_PROTO_DRDA, "DRDA" },
    { ND_PROTO_DROPBOX, "Dropbox" },
    { ND_PROTO_DTLS, "DTLS" },
    { ND_PROTO_EAQ, "EAQ" },
    { ND_PROTO_ELASTICSEARCH, "ElasticSearch" },
    { ND_PROTO_ETHERNET_IP, "EtherNet/IP" },
    { ND_PROTO_FASTCGI, "FastCGI" },
    { ND_PROTO_FIX, "FIX" },
    { ND_PROTO_FTPS, "FTP/S" },
    { ND_PROTO_FTP_CONTROL, "FTP/C" },
    { ND_PROTO_FTP_DATA, "FTP/D" },
    { ND_PROTO_GENSHIN_IMPACT, "Genshin/Impact" },
    { ND_PROTO_GIT, "Git" },
    { ND_PROTO_GNUTELLA, "Gnutella" },
    { ND_PROTO_GOOGLE_MEET_DUO, "Google/Meet/Duo" },
    { ND_PROTO_GTP, "GTP" },
    { ND_PROTO_GTP_C, "GTP/C" },
    { ND_PROTO_GTP_P, "GTP/P" },
    { ND_PROTO_GTP_U, "GTP/U" },
    { ND_PROTO_GUILDWARS, "Guildwars" },
    { ND_PROTO_H323, "H323" },
    { ND_PROTO_HALFLIFE2, "HalfLife2" },
    { ND_PROTO_HP_VIRTGRP, "HP/VirtGrp" },
    { ND_PROTO_HTTP, "HTTP" },
    { ND_PROTO_HTTPS, "HTTP/S" },
    { ND_PROTO_HTTP_CONNECT, "HTTP/Connect" },
    { ND_PROTO_HTTP_PROXY, "HTTP/Proxy" },
    { ND_PROTO_I3D, "i3D" },
    { ND_PROTO_IAX, "IAX" },
    { ND_PROTO_ICECAST, "IceCast" },
    { ND_PROTO_IEC60870_5_104, "IEC60870/5/104" },
    { ND_PROTO_IPP, "IPP" },
    { ND_PROTO_IPSEC, "IPSEC" },
    { ND_PROTO_IP_EGP, "EGP" },
    { ND_PROTO_IP_GRE, "GRE" },
    { ND_PROTO_IP_ICMP, "ICMP" },
    { ND_PROTO_IP_ICMPV6, "ICMPv6" },
    { ND_PROTO_IP_IGMP, "IGMP" },
    { ND_PROTO_IP_IP_IN_IP, "IPinIP" },
    { ND_PROTO_IP_OSPF, "OSPF" },
    { ND_PROTO_IP_PGM, "PGM" },
    { ND_PROTO_IP_PIM, "PIM" },
    { ND_PROTO_IP_SCTP, "SCTP" },
    { ND_PROTO_IP_VRRP, "VRRP" },
    { ND_PROTO_IRC, "IRC" },
    { ND_PROTO_IRCS, "IRC/S" },
    { ND_PROTO_KAKAOTALK_VOICE, "KakaoTalk/Voice" },
    { ND_PROTO_KERBEROS, "Kerberos" },
    { ND_PROTO_KISMET, "KISMET" },
    { ND_PROTO_KONTIKI, "Kontiki" },
    { ND_PROTO_LDAP, "LDAP" },
    { ND_PROTO_LINE_CALL, "Line/Call" },
    { ND_PROTO_LISP, "LISP" },
    { ND_PROTO_LLMNR, "LLMNR" },
    { ND_PROTO_LOTUS_NOTES, "LotusNotes" },
    { ND_PROTO_MAIL_IMAP, "IMAP" },
    { ND_PROTO_MAIL_IMAPS, "IMAP/S" },
    { ND_PROTO_MAIL_POP, "POP3" },
    { ND_PROTO_MAIL_POPS, "POP3/S" },
    { ND_PROTO_MAIL_SMTP, "SMTP" },
    { ND_PROTO_MAIL_SMTPS, "SMTP/S" },
    { ND_PROTO_MAPLESTORY, "MapleStory" },
    { ND_PROTO_MDNS, "MDNS" },
    { ND_PROTO_MEGACO, "Megaco" },
    { ND_PROTO_MEMCACHED, "Memcached" },
    { ND_PROTO_MERAKI_CLOUD, "Meraki/Cloud" },
    { ND_PROTO_MGCP, "MGCP" },
    { ND_PROTO_MINING, "Mining" },
    { ND_PROTO_MODBUS, "Modbus" },
    { ND_PROTO_MONGODB, "MongoDB" },
    { ND_PROTO_MPEGDASH, "MPEG/Dash" },
    { ND_PROTO_MPEGTS, "MPEGTS" },
    { ND_PROTO_MQTT, "MQTT" },
    { ND_PROTO_MQTTS, "MQTT/S" },
    { ND_PROTO_MSSQL_TDS, "MSSQL/TDS" },
    { ND_PROTO_MUNIN, "Munin" },
    { ND_PROTO_MYSQL, "MYSQL" },
    { ND_PROTO_NATPMP, "NAT/PMP" },
    { ND_PROTO_NATS, "NATS" },
    { ND_PROTO_NEST_LOG_SINK, "NestLog" },
    { ND_PROTO_NETBIOS, "NETBIOS" },
    { ND_PROTO_NETFLOW, "NetFlow" },
    { ND_PROTO_NFS, "NFS" },
    { ND_PROTO_NINTENDO, "Nintendo" },
    { ND_PROTO_NNTP, "NNTP" },
    { ND_PROTO_NNTPS, "NNTP/S" },
    { ND_PROTO_NOE, "NOE" },
    { ND_PROTO_NTP, "NTP" },
    { ND_PROTO_OOKLA, "OOKLA" },
    { ND_PROTO_OPENVPN, "OpenVPN" },
    { ND_PROTO_ORACLE, "Oracle" },
    { ND_PROTO_POSTGRES, "PGSQL" },
    { ND_PROTO_PPSTREAM, "PPStream" },
    { ND_PROTO_PPTP, "PPTP" },
    { ND_PROTO_QQ, "QQ" },
    { ND_PROTO_QQLIVE, "QQLive" },
    { ND_PROTO_QUIC, "QUIC" },
    { ND_PROTO_RADIUS, "RADIUS" },
    { ND_PROTO_RAKNET, "RakNet" },
    { ND_PROTO_RDP, "RDP" },
    { ND_PROTO_REDIS, "Redis" },
    { ND_PROTO_REMOTE_SCAN, "RemoteScan" },
    { ND_PROTO_RIOTGAMES, "Riot/Games" },
    { ND_PROTO_RPC, "RPC" },
    { ND_PROTO_RSH, "RSH" },
    { ND_PROTO_RSYNC, "RSYNC" },
    { ND_PROTO_RTCP, "RTCP" },
    { ND_PROTO_RTMP, "RTMP" },
    { ND_PROTO_RTP, "RTP" },
    { ND_PROTO_RTSP, "RTSP" },
    { ND_PROTO_RX, "RX" },
    { ND_PROTO_S7COMM, "S7comm" },
    { ND_PROTO_SAP, "SAP" },
    { ND_PROTO_SD_RTN, "SD/RTN" },
    { ND_PROTO_SFLOW, "SFlow" },
    { ND_PROTO_SIGNAL_CALL, "SignalCall" },
    { ND_PROTO_SIP, "SIP" },
    { ND_PROTO_SIPS, "SIP/S" },
    { ND_PROTO_SKYPE_TEAMS, "Skype/Teams" },
    { ND_PROTO_SKYPE_TEAMS_CALL, "Skype/Teams/Call" },
    { ND_PROTO_SMBV1, "SMBv1" },
    { ND_PROTO_SMBV23, "SMBv23" },
    { ND_PROTO_SMPP, "SMPP" },
    { ND_PROTO_SNAPCHAT_CALL, "Snapchat/Call" },
    { ND_PROTO_SNMP, "SNMP" },
    { ND_PROTO_SOAP, "SOAP" },
    { ND_PROTO_SOCKS, "SOCKS" },
    { ND_PROTO_SOMEIP, "SOMEIP" },
    { ND_PROTO_SPOTIFY, "Spotify" },
    { ND_PROTO_SSDP, "SSDP" },
    { ND_PROTO_SSH, "SSH" },
    { ND_PROTO_STARCRAFT, "Starcraft" },
    { ND_PROTO_STEAM, "Steam" },
    { ND_PROTO_STUN, "STUN" },
    { ND_PROTO_SYNCTHING, "Syncthing" },
    { ND_PROTO_SYSLOG, "SYSLOG" },
    { ND_PROTO_SYSLOGS, "SYSLOG/S" },
    { ND_PROTO_TAILSCALE, "Tailscale" },
    { ND_PROTO_TARGUS_GETDATA, "Targus/Dataspeed" },
    { ND_PROTO_TEAMSPEAK, "TeamSpeak" },
    { ND_PROTO_TEAMVIEWER, "TeamViewer" },
    { ND_PROTO_TELEGRAM, "Telegram" },
    { ND_PROTO_TELNET, "Telnet" },
    { ND_PROTO_TEREDO, "Teredo" },
    { ND_PROTO_TFTP, "TFTP" },
    { ND_PROTO_THREEMA, "Threema" },
    { ND_PROTO_TINC, "TINC" },
    { ND_PROTO_TIVOCONNECT, "TiVo/Connect" },
    { ND_PROTO_TLS, "TLS" },
    { ND_PROTO_TOCA_BOCA, "TocaBoca" },
    { ND_PROTO_TODO, "TODO" },
    { ND_PROTO_TPLINK_SHP, "TPLINK/SHP" },
    { ND_PROTO_TRUPHONE, "TruPhone" },
    { ND_PROTO_TUYA_LP, "Tuya/LP" },
    { ND_PROTO_TVUPLAYER, "TVUplayer" },
    { ND_PROTO_UBNTAC2, "UBNTAC2" },
    { ND_PROTO_ULTRASURF, "UltraSurf" },
    { ND_PROTO_UNKNOWN, "Unknown" },
    { ND_PROTO_VHUA, "VHUA" },
    { ND_PROTO_VIBER, "Viber" },
    { ND_PROTO_VMWARE, "VMWARE" },
    { ND_PROTO_VNC, "VNC" },
    { ND_PROTO_VXLAN, "VXLAN" },
    { ND_PROTO_WARCRAFT3, "Warcraft3" },
    { ND_PROTO_WEBSOCKET, "Websocket" },
    { ND_PROTO_WHATSAPP, "WhatsApp" },
    { ND_PROTO_WHATSAPP_CALL, "WhatsApp/Call" },
    { ND_PROTO_WHOIS_DAS, "Whois/DAS" },
    { ND_PROTO_WIREGUARD, "WireGuard" },
    { ND_PROTO_WORLDOFKUNGFU, "WoKungFu" },
    { ND_PROTO_WORLDOFWARCRAFT, "WoW" },
    { ND_PROTO_WSD, "WSD" },
    { ND_PROTO_XBOX, "Xbox" },
    { ND_PROTO_XDMCP, "XDMCP" },
    { ND_PROTO_XIAOMI, "Xiaomi" },
    { ND_PROTO_XMPP, "XMPP" },
    { ND_PROTO_Z3950, "Z39/50" },
    { ND_PROTO_ZABBIX, "Zabbix" },
    { ND_PROTO_ZATTOO, "Zattoo" },
    { ND_PROTO_ZMQ, "ZMQ" },
    { ND_PROTO_ZOOM, "ZOOM" },
};

inline const char *nd_proto_get_name(nd_proto_id_t id)
{
    nd_protos_t::const_iterator it;
    if ((it = nd_protos.find(id)) == nd_protos.end())
        return "Unknown";
    return it->second;
}

inline unsigned nd_proto_get_id(const string &name)
{
    for (auto &it : nd_protos) {
        if (strcasecmp(it.second, name.c_str())) continue;
        return it.first;
    }
    return ND_PROTO_UNKNOWN;
}

typedef unordered_map<uint16_t, nd_proto_id_t> nd_ndpi_proto_t;

const nd_ndpi_proto_t nd_ndpi_protos = {
    { NDPI_PROTOCOL_AFP, ND_PROTO_AFP },
    { NDPI_PROTOCOL_AJP, ND_PROTO_AJP },
    { NDPI_PROTOCOL_ALICLOUD, ND_PROTO_ALICLOUD },
    { NDPI_PROTOCOL_AMONG_US, ND_PROTO_AMONG_US },
    { NDPI_PROTOCOL_AMQP, ND_PROTO_AMQP },
    { NDPI_PROTOCOL_APPLE_PUSH, ND_PROTO_APPLE_PUSH },
    { NDPI_PROTOCOL_ARMAGETRON, ND_PROTO_ARMAGETRON },
    { NDPI_PROTOCOL_AVAST, ND_PROTO_AVAST },
    { NDPI_PROTOCOL_AVAST_SECUREDNS, ND_PROTO_AVAST_SDNS },
    { NDPI_PROTOCOL_BGP, ND_PROTO_BGP },
    { NDPI_PROTOCOL_BITTORRENT, ND_PROTO_BITTORRENT },
    { NDPI_PROTOCOL_BJNP, ND_PROTO_BJNP },
    { NDPI_PROTOCOL_CAPWAP, ND_PROTO_CAPWAP },
    { NDPI_PROTOCOL_CASSANDRA, ND_PROTO_CASSANDRA },
    { NDPI_PROTOCOL_CHECKMK, ND_PROTO_CHECKMK },
    { NDPI_PROTOCOL_CISCOVPN, ND_PROTO_CISCO_VPN },
    { NDPI_PROTOCOL_CITRIX, ND_PROTO_CITRIX },
    { NDPI_PROTOCOL_COAP, ND_PROTO_COAP },
    { NDPI_PROTOCOL_COLLECTD, ND_PROTO_COLLECTD },
    { NDPI_PROTOCOL_CORBA, ND_PROTO_CORBA },
    { NDPI_PROTOCOL_CPHA, ND_PROTO_CPHA },
    { NDPI_PROTOCOL_CROSSFIRE, ND_PROTO_CROSSFIRE },
    { NDPI_PROTOCOL_CRYNET, ND_PROTO_CRYNET },
    { NDPI_PROTOCOL_CSGO, ND_PROTO_CSGO },
    { NDPI_PROTOCOL_DATASAVER, ND_PROTO_DATASAVER },
    { NDPI_PROTOCOL_DHCP, ND_PROTO_DHCP },
    { NDPI_PROTOCOL_DHCPV6, ND_PROTO_DHCPV6 },
    { NDPI_PROTOCOL_DIAMETER, ND_PROTO_DIAMETER },
    { NDPI_PROTOCOL_DNP3, ND_PROTO_DNP3 },
    { NDPI_PROTOCOL_DNS, ND_PROTO_DNS },
    { NDPI_PROTOCOL_DNSCRYPT, ND_PROTO_DNSCRYPT },
    { NDPI_PROTOCOL_DOFUS, ND_PROTO_DOFUS },
    { NDPI_PROTOCOL_DOH_DOT, ND_PROTO_DOQ },
    { NDPI_PROTOCOL_DRDA, ND_PROTO_DRDA },
    { NDPI_PROTOCOL_DROPBOX, ND_PROTO_DROPBOX },
    { NDPI_PROTOCOL_DTLS, ND_PROTO_DTLS },
    { NDPI_PROTOCOL_EAQ, ND_PROTO_EAQ },
    { NDPI_PROTOCOL_ELASTICSEARCH, ND_PROTO_ELASTICSEARCH },
    { NDPI_PROTOCOL_ETHERNET_IP, ND_PROTO_ETHERNET_IP },
    { NDPI_PROTOCOL_FASTCGI, ND_PROTO_FASTCGI },
    { NDPI_PROTOCOL_FIX, ND_PROTO_FIX },
    { NDPI_PROTOCOL_FTPS, ND_PROTO_FTPS },
    { NDPI_PROTOCOL_FTP_CONTROL, ND_PROTO_FTP_CONTROL },
    { NDPI_PROTOCOL_FTP_DATA, ND_PROTO_FTP_DATA },
    { NDPI_PROTOCOL_GENSHIN_IMPACT, ND_PROTO_GENSHIN_IMPACT },
    { NDPI_PROTOCOL_GIT, ND_PROTO_GIT },
    { NDPI_PROTOCOL_GNUTELLA, ND_PROTO_GNUTELLA },
    { NDPI_PROTOCOL_GTP, ND_PROTO_GTP },
    { NDPI_PROTOCOL_GTP_C, ND_PROTO_GTP_C },
    { NDPI_PROTOCOL_GTP_PRIME, ND_PROTO_GTP_P },
    { NDPI_PROTOCOL_GTP_U, ND_PROTO_GTP_U },
    { NDPI_PROTOCOL_GUILDWARS, ND_PROTO_GUILDWARS },
    { NDPI_PROTOCOL_H323, ND_PROTO_H323 },
    { NDPI_PROTOCOL_HALFLIFE2, ND_PROTO_HALFLIFE2 },
    { NDPI_PROTOCOL_HANGOUT_DUO, ND_PROTO_GOOGLE_MEET_DUO },
    { NDPI_PROTOCOL_HPVIRTGRP, ND_PROTO_HP_VIRTGRP },
    { NDPI_PROTOCOL_HSRP, ND_PROTO_CISCO_HSRP },
    { NDPI_PROTOCOL_HTTP, ND_PROTO_HTTP },
    { NDPI_PROTOCOL_HTTP_CONNECT, ND_PROTO_HTTP_CONNECT },
    { NDPI_PROTOCOL_HTTP_PROXY, ND_PROTO_HTTP_PROXY },
    { NDPI_PROTOCOL_I3D, ND_PROTO_I3D },
    { NDPI_PROTOCOL_IAX, ND_PROTO_IAX },
    { NDPI_PROTOCOL_ICECAST, ND_PROTO_ICECAST },
    { NDPI_PROTOCOL_IEC60870, ND_PROTO_IEC60870_5_104 },
    { NDPI_PROTOCOL_IPP, ND_PROTO_IPP },
    { NDPI_PROTOCOL_IPSEC, ND_PROTO_IPSEC },
    { NDPI_PROTOCOL_IP_EGP, ND_PROTO_IP_EGP },
    { NDPI_PROTOCOL_IP_GRE, ND_PROTO_IP_GRE },
    { NDPI_PROTOCOL_IP_ICMP, ND_PROTO_IP_ICMP },
    { NDPI_PROTOCOL_IP_ICMPV6, ND_PROTO_IP_ICMPV6 },
    { NDPI_PROTOCOL_IP_IGMP, ND_PROTO_IP_IGMP },
    { NDPI_PROTOCOL_IP_IP_IN_IP, ND_PROTO_IP_IP_IN_IP },
    { NDPI_PROTOCOL_IP_OSPF, ND_PROTO_IP_OSPF },
    { NDPI_PROTOCOL_IP_PGM, ND_PROTO_IP_PGM },
    { NDPI_PROTOCOL_IP_PIM, ND_PROTO_IP_PIM },
    { NDPI_PROTOCOL_IP_SCTP, ND_PROTO_IP_SCTP },
    { NDPI_PROTOCOL_IP_VRRP, ND_PROTO_IP_VRRP },
    { NDPI_PROTOCOL_IRC, ND_PROTO_IRC },
    { NDPI_PROTOCOL_JABBER, ND_PROTO_XMPP },
    { NDPI_PROTOCOL_KAKAOTALK_VOICE, ND_PROTO_KAKAOTALK_VOICE },
    { NDPI_PROTOCOL_KERBEROS, ND_PROTO_KERBEROS },
    { NDPI_PROTOCOL_KISMET, ND_PROTO_KISMET },
    { NDPI_PROTOCOL_KONTIKI, ND_PROTO_KONTIKI },
    { NDPI_PROTOCOL_LDAP, ND_PROTO_LDAP },
    { NDPI_PROTOCOL_LINE_CALL, ND_PROTO_LINE_CALL },
    { NDPI_PROTOCOL_LISP, ND_PROTO_LISP },
    { NDPI_PROTOCOL_LLMNR, ND_PROTO_LLMNR },
    { NDPI_PROTOCOL_LOTUS_NOTES, ND_PROTO_LOTUS_NOTES },
    { NDPI_PROTOCOL_MAIL_IMAP, ND_PROTO_MAIL_IMAP },
    { NDPI_PROTOCOL_MAIL_IMAPS, ND_PROTO_MAIL_IMAPS },
    { NDPI_PROTOCOL_MAIL_POP, ND_PROTO_MAIL_POP },
    { NDPI_PROTOCOL_MAIL_POPS, ND_PROTO_MAIL_POPS },
    { NDPI_PROTOCOL_MAIL_SMTP, ND_PROTO_MAIL_SMTP },
    { NDPI_PROTOCOL_MAIL_SMTPS, ND_PROTO_MAIL_SMTPS },
    { NDPI_PROTOCOL_MAPLESTORY, ND_PROTO_MAPLESTORY },
    { NDPI_PROTOCOL_MDNS, ND_PROTO_MDNS },
    { NDPI_PROTOCOL_MEGACO, ND_PROTO_MEGACO },
    { NDPI_PROTOCOL_MEMCACHED, ND_PROTO_MEMCACHED },
    { NDPI_PROTOCOL_MERAKI_CLOUD, ND_PROTO_MERAKI_CLOUD },
    { NDPI_PROTOCOL_MGCP, ND_PROTO_MGCP },
    { NDPI_PROTOCOL_MINING, ND_PROTO_MINING },
    { NDPI_PROTOCOL_MODBUS, ND_PROTO_MODBUS },
    { NDPI_PROTOCOL_MONGODB, ND_PROTO_MONGODB },
    { NDPI_PROTOCOL_MPEGDASH, ND_PROTO_MPEGDASH },
    { NDPI_PROTOCOL_MPEGTS, ND_PROTO_MPEGTS },
    { NDPI_PROTOCOL_MQTT, ND_PROTO_MQTT },
    { NDPI_PROTOCOL_MSSQL_TDS, ND_PROTO_MSSQL_TDS },
    { NDPI_PROTOCOL_MUNIN, ND_PROTO_MUNIN},
    { NDPI_PROTOCOL_MYSQL, ND_PROTO_MYSQL },
    { NDPI_PROTOCOL_NATPMP, ND_PROTO_NATPMP },
    { NDPI_PROTOCOL_NATS, ND_PROTO_NATS },
    { NDPI_PROTOCOL_NEST_LOG_SINK, ND_PROTO_NEST_LOG_SINK },
    { NDPI_PROTOCOL_NETBIOS, ND_PROTO_NETBIOS },
    { NDPI_PROTOCOL_NETFLOW, ND_PROTO_NETFLOW },
    { NDPI_PROTOCOL_NFS, ND_PROTO_NFS },
    { NDPI_PROTOCOL_NINTENDO, ND_PROTO_NINTENDO },
    { NDPI_PROTOCOL_NOE, ND_PROTO_NOE },
    { NDPI_PROTOCOL_NTP, ND_PROTO_NTP },
    { NDPI_PROTOCOL_OOKLA, ND_PROTO_OOKLA },
    { NDPI_PROTOCOL_OPENVPN, ND_PROTO_OPENVPN },
    { NDPI_PROTOCOL_ORACLE, ND_PROTO_ORACLE },
    { NDPI_PROTOCOL_POSTGRES, ND_PROTO_POSTGRES },
    { NDPI_PROTOCOL_PPSTREAM, ND_PROTO_PPSTREAM },
    { NDPI_PROTOCOL_PPTP, ND_PROTO_PPTP },
    { NDPI_PROTOCOL_QQ, ND_PROTO_QQ },
    { NDPI_PROTOCOL_QUIC, ND_PROTO_QUIC },
    { NDPI_PROTOCOL_RADIUS, ND_PROTO_RADIUS },
    { NDPI_PROTOCOL_RAKNET, ND_PROTO_RAKNET },
    { NDPI_PROTOCOL_RDP, ND_PROTO_RDP },
    { NDPI_PROTOCOL_REDIS, ND_PROTO_REDIS },
    { NDPI_PROTOCOL_RIOTGAMES, ND_PROTO_RIOTGAMES },
    { NDPI_PROTOCOL_RPC, ND_PROTO_RPC },
    { NDPI_PROTOCOL_RSH, ND_PROTO_RSH },
    { NDPI_PROTOCOL_RSYNC, ND_PROTO_RSYNC },
    { NDPI_PROTOCOL_RTCP, ND_PROTO_RTCP },
    { NDPI_PROTOCOL_RTMP, ND_PROTO_RTMP },
    { NDPI_PROTOCOL_RTP, ND_PROTO_RTP },
    { NDPI_PROTOCOL_RTSP, ND_PROTO_RTSP },
    { NDPI_PROTOCOL_RX, ND_PROTO_RX },
    { NDPI_PROTOCOL_S7COMM, ND_PROTO_S7COMM },
    { NDPI_PROTOCOL_SAP, ND_PROTO_SAP },
    { NDPI_PROTOCOL_SD_RTN, ND_PROTO_SD_RTN },
    { NDPI_PROTOCOL_SFLOW, ND_PROTO_SFLOW },
    { NDPI_PROTOCOL_SIGNAL_VOIP, ND_PROTO_SIGNAL_CALL },
    { NDPI_PROTOCOL_SIP, ND_PROTO_SIP },
    { NDPI_PROTOCOL_SKINNY, ND_PROTO_CISCO_SKINNY },
    { NDPI_PROTOCOL_SKYPE_TEAMS, ND_PROTO_SKYPE_TEAMS },
    { NDPI_PROTOCOL_SKYPE_TEAMS_CALL, ND_PROTO_SKYPE_TEAMS_CALL },
    { NDPI_PROTOCOL_SMBV1, ND_PROTO_SMBV1 },
    { NDPI_PROTOCOL_SMBV23, ND_PROTO_SMBV23 },
    { NDPI_PROTOCOL_SMPP, ND_PROTO_SMPP },
    { NDPI_PROTOCOL_SNAPCHAT_CALL, ND_PROTO_SNAPCHAT_CALL },
    { NDPI_PROTOCOL_SNMP, ND_PROTO_SNMP },
    { NDPI_PROTOCOL_SOAP, ND_PROTO_SOAP },
    { NDPI_PROTOCOL_SOCKS, ND_PROTO_SOCKS },
    { NDPI_PROTOCOL_SOMEIP, ND_PROTO_SOMEIP },
    { NDPI_PROTOCOL_SPOTIFY, ND_PROTO_SPOTIFY },
    { NDPI_PROTOCOL_SSDP, ND_PROTO_SSDP },
    { NDPI_PROTOCOL_SSH, ND_PROTO_SSH },
    { NDPI_PROTOCOL_STARCRAFT, ND_PROTO_STARCRAFT },
    { NDPI_PROTOCOL_STEAM, ND_PROTO_STEAM },
    { NDPI_PROTOCOL_STUN, ND_PROTO_STUN },
    { NDPI_PROTOCOL_SYNCTHING, ND_PROTO_SYNCTHING },
    { NDPI_PROTOCOL_SYSLOG, ND_PROTO_SYSLOG },
    { NDPI_PROTOCOL_TAILSCALE, ND_PROTO_TAILSCALE },
    { NDPI_PROTOCOL_TARGUS_GETDATA, ND_PROTO_TARGUS_GETDATA },
    { NDPI_PROTOCOL_TEAMSPEAK, ND_PROTO_TEAMSPEAK },
    { NDPI_PROTOCOL_TEAMVIEWER, ND_PROTO_TEAMVIEWER },
    { NDPI_PROTOCOL_TELEGRAM, ND_PROTO_TELEGRAM },
    { NDPI_PROTOCOL_TELNET, ND_PROTO_TELNET },
    { NDPI_PROTOCOL_TEREDO, ND_PROTO_TEREDO },
    { NDPI_PROTOCOL_TFTP, ND_PROTO_TFTP },
    { NDPI_PROTOCOL_THREEMA, ND_PROTO_THREEMA },
    { NDPI_PROTOCOL_TIKTOK, ND_PROTO_TIKTOK },
    { NDPI_PROTOCOL_TINC, ND_PROTO_TINC },
    { NDPI_PROTOCOL_TIVOCONNECT, ND_PROTO_TIVOCONNECT },
    { NDPI_PROTOCOL_TLS, ND_PROTO_TLS },
    { NDPI_PROTOCOL_TOCA_BOCA, ND_PROTO_TOCA_BOCA },
    { NDPI_PROTOCOL_TPLINK_SHP, ND_PROTO_TPLINK_SHP },
    { NDPI_PROTOCOL_TRUPHONE, ND_PROTO_TRUPHONE },
    { NDPI_PROTOCOL_TUYA_LP, ND_PROTO_TUYA_LP },
    { NDPI_PROTOCOL_TVUPLAYER, ND_PROTO_TVUPLAYER },
    { NDPI_PROTOCOL_UBNTAC2, ND_PROTO_UBNTAC2 },
    { NDPI_PROTOCOL_ULTRASURF, ND_PROTO_ULTRASURF },
    { NDPI_PROTOCOL_UNKNOWN, ND_PROTO_UNKNOWN },
    { NDPI_PROTOCOL_USENET, ND_PROTO_NNTP },
    { NDPI_PROTOCOL_VHUA, ND_PROTO_VHUA },
    { NDPI_PROTOCOL_VIBER, ND_PROTO_VIBER },
    { NDPI_PROTOCOL_VMWARE, ND_PROTO_VMWARE },
    { NDPI_PROTOCOL_VNC, ND_PROTO_VNC },
    { NDPI_PROTOCOL_VXLAN, ND_PROTO_VXLAN },
    { NDPI_PROTOCOL_WARCRAFT3, ND_PROTO_WARCRAFT3 },
    { NDPI_PROTOCOL_WEBSOCKET, ND_PROTO_WEBSOCKET },
    { NDPI_PROTOCOL_WHATSAPP, ND_PROTO_WHATSAPP },
    { NDPI_PROTOCOL_WHATSAPP_CALL, ND_PROTO_WHATSAPP_CALL },
    { NDPI_PROTOCOL_WHOIS_DAS, ND_PROTO_WHOIS_DAS },
    { NDPI_PROTOCOL_WIREGUARD, ND_PROTO_WIREGUARD },
    { NDPI_PROTOCOL_WORLDOFWARCRAFT, ND_PROTO_WORLDOFWARCRAFT },
    { NDPI_PROTOCOL_WORLD_OF_KUNG_FU, ND_PROTO_WORLDOFKUNGFU },
    { NDPI_PROTOCOL_WSD, ND_PROTO_WSD },
    { NDPI_PROTOCOL_XBOX, ND_PROTO_XBOX },
    { NDPI_PROTOCOL_XDMCP, ND_PROTO_XDMCP },
    { NDPI_PROTOCOL_XIAOMI, ND_PROTO_XIAOMI },
    { NDPI_PROTOCOL_Z3950, ND_PROTO_Z3950 },
    { NDPI_PROTOCOL_ZABBIX, ND_PROTO_ZABBIX },
    { NDPI_PROTOCOL_ZATTOO, ND_PROTO_ZATTOO },
    { NDPI_PROTOCOL_ZMQ, ND_PROTO_ZMQ },
    { NDPI_PROTOCOL_ZOOM, ND_PROTO_ZOOM },
};

typedef vector<uint16_t> nd_ndpi_disabled_protos_t;

const nd_ndpi_disabled_protos_t nd_ndpi_disabled_protos = {
    NDPI_PROTOCOL_1KXUN,        // Not a protocol (no dissector): ID# 295 (1kxun)
    NDPI_PROTOCOL_ACCUWEATHER,  // Not a protocol: ID# 280 (AccuWeather)
    NDPI_PROTOCOL_ACTIVISION,   // Not a protocol (no dissector): ID# 258 (Activision)
    NDPI_PROTOCOL_ALIBABA,      // Not a protocol (see ALICLOUD): ID# 274 (Alibaba)
    NDPI_PROTOCOL_AMAZON_ALEXA, // Not a protocol (no dissector): ID# 110 (AmazonAlexa)
    NDPI_PROTOCOL_AMAZON_AWS,   // Not a protocol (no dissector): ID# 265 (AmazonAWS)
    NDPI_PROTOCOL_AMAZON,       // Not a protocol: ID# 178 (Amazon)
    NDPI_PROTOCOL_AMAZON_VIDEO, // No detections and no pcap to test.
    NDPI_PROTOCOL_ANYDESK,      // Not a protocol (no dissector): ID# 252 (AnyDesk)
    NDPI_PROTOCOL_APPLE_ICLOUD, // Not a protocol (no dissector): ID# 143 (AppleiCloud)
    NDPI_PROTOCOL_APPLE_ITUNES, // Not a protocol (no dissector): ID# 145 (AppleiTunes)
    NDPI_PROTOCOL_APPLE,        // Not a protocol: ID# 140 (Apple)
    NDPI_PROTOCOL_APPLE_SIRI,   // Not a protocol (no dissector): ID# 254 (AppleSiri)
    NDPI_PROTOCOL_APPLESTORE,   // Not a protocol: ID# 224 (AppleStore)
    NDPI_PROTOCOL_APPLETVPLUS,  // Not a protocol (no dissector): ID# 317 (AppleTVPlus)
    NDPI_PROTOCOL_BADOO,        // Not a protocol: ID# 279 (Badoo)
    NDPI_PROTOCOL_BLOOMBERG,    // Not a protocol: ID# 246 (Bloomberg)
    NDPI_PROTOCOL_CACHEFLY,     // Not a protocol: ID# 289 (Cachefly)
    NDPI_PROTOCOL_CLOUDFLARE,   // Not a protocol: ID# 220 (Cloudflare)
    NDPI_PROTOCOL_CLOUDFLARE_WARP, // Not a protocol: ID# 300 (CloudflareWarp)
    NDPI_PROTOCOL_CNN,          // Not a protocol: ID# 180 (CNN)
    NDPI_PROTOCOL_CRASHLYSTICS, // Not a protocol (no dissector): ID# 275 (Crashlytics)
    NDPI_PROTOCOL_CYBERSECURITY, // Not a protocol: ID# 283 (Cybersec)
    NDPI_PROTOCOL_DAILYMOTION,  // Not a protocol: ID# 322 (Dailymotion)
    NDPI_PROTOCOL_DAZN,         // Not a protocol: ID# 292 (Dazn)
    NDPI_PROTOCOL_DEEZER,       // Not a protocol: ID# 210 (Deezer)
    NDPI_PROTOCOL_DIRECTV,      // Not a protocol (no dissector): ID# 318 (DirecTV)
    NDPI_PROTOCOL_DISCORD,      // Not a protocol (no dissector): ID# 58 (Discord)
    NDPI_PROTOCOL_DISNEYPLUS,   // Not a protocol: ID# 71 (DisneyPlus)
    NDPI_PROTOCOL_EBAY,         // Not a protocol: ID# 179 (eBay)
    NDPI_PROTOCOL_EDGECAST,     // Not a protocol (no dissector): ID# 288 (Edgecast)
    NDPI_PROTOCOL_EDONKEY,      // Garbage; false-positives.
    NDPI_PROTOCOL_FACEBOOK,     // Not a protocol: ID# 119 (Facebook)
    NDPI_PROTOCOL_FACEBOOK_VOIP, // Not a protocol (no dissector): ID# 268 (FacebookVoip)
    NDPI_PROTOCOL_FORTICLIENT,  // Not a protocol (no dissector): ID# 259 (FortiClient)
    NDPI_PROTOCOL_FUZE,         // Not a protocol: ID# 270 (Fuze)
    NDPI_PROTOCOL_GITHUB,       // Not a protocol: ID# 203 (Github)
    NDPI_PROTOCOL_GITLAB,       // Not a protocol: ID# 262 (GitLab)
    NDPI_PROTOCOL_GMAIL,        // Not a protocol: ID# 122 (GMail)
    NDPI_PROTOCOL_GOOGLE_CLASSROOM, // Not a protocol: ID# 281 (GoogleClassroom)
    NDPI_PROTOCOL_GOOGLE_CLOUD, // Not a protocol: ID# 284 (GoogleCloud)
    NDPI_PROTOCOL_GOOGLE_DOCS,  // Not a protocol: ID# 241 (GoogleDocs)
    NDPI_PROTOCOL_GOOGLE_DRIVE, // Not a protocol (no dissector): ID# 217 (GoogleDrive)
    NDPI_PROTOCOL_GOOGLE_MAPS,  // Not a protocol: ID# 123 (GoogleMaps)
    NDPI_PROTOCOL_GOOGLE,       // Not a protocol: ID# 126 (Google)
    NDPI_PROTOCOL_GOOGLE_PLUS,  // Not a protocol: ID# 72 (GooglePlus)
    NDPI_PROTOCOL_GOOGLE_SERVICES, // Not a protocol: ID# 239 (GoogleServices)
    NDPI_PROTOCOL_GOTO,         // Not a protocol: ID# 293 (GoTo)
    NDPI_PROTOCOL_HBO,          // Not a protocol: ID# 319 (HBO)
    NDPI_PROTOCOL_HOTSPOT_SHIELD, // Not a protocol: ID# 215 (HotspotShield)
    NDPI_PROTOCOL_HULU,         // Not a protocol: ID# 137 (Hulu)
    NDPI_PROTOCOL_ICLOUD_PRIVATE_RELAY, // Not a protocol (no dissector): ID# 277 (iCloudPrivateRelay)
    NDPI_PROTOCOL_IFLIX,        // Not a protocol: ID# 202 (IFLIX)
    NDPI_PROTOCOL_IHEARTRADIO,  // Not a protocol: ID# 325 (IHeartRadio)
    NDPI_PROTOCOL_IMO,          // Weak, too many false-positives, and obscure/undocumented.
    NDPI_PROTOCOL_INSTAGRAM,    // Not a protocol: ID# 211 (Instagram)
    NDPI_PROTOCOL_KAKAOTALK,    // Not a protocol (see KAKAOTALK_VOICE): ID# 193 (KakaoTalk)
    NDPI_PROTOCOL_LASTFM,       // Not a protocol: ID# 134 (LastFM)
    NDPI_PROTOCOL_LIKEE,        // Not a protocol: ID# 261 (Likee)
    NDPI_PROTOCOL_LINE,         // Not a protocol: ID# 315 (Line)
    NDPI_PROTOCOL_LINKEDIN,     // Not a protocol: ID# 233 (LinkedIn)
    NDPI_PROTOCOL_LIVESTREAM,   // Not a protocol: ID# 323 (Livestream)
    NDPI_PROTOCOL_MESSENGER,    // Not a protocol (no dissector): ID# 157 (Messenger)
    NDPI_PROTOCOL_MICROSOFT_365, // Not a protocol: ID# 219 (Microsoft365)
    NDPI_PROTOCOL_MICROSOFT_AZURE, // Not a protocol (no dissector): ID# 276 (Azure)
    NDPI_PROTOCOL_MICROSOFT,    // Not a protocol: ID# 212 (Microsoft)
    NDPI_PROTOCOL_MS_ONE_DRIVE, // Not a protocol (no dissector): ID# 221 (MS_OneDrive)
    NDPI_PROTOCOL_MS_OUTLOOK,   // Not a protocol: ID# 21 (Outlook)
    NDPI_PROTOCOL_MSTEAMS,      // Not a protocol (see SKYPE_TEAMS_CALL): ID# 250 (Teams)
    NDPI_PROTOCOL_NETFLIX,      // Not a protocol: ID# 133 (NetFlix)
    NDPI_PROTOCOL_NTOP,         // Not a protocol: ID# 26 (ntop)
    NDPI_PROTOCOL_OCS,          // Not a protocol: ID# 218 (OCS)
    NDPI_PROTOCOL_OCSP,         // Not a protocol (HTTP): ID# 63 (OCSP)
    NDPI_PROTOCOL_OPENDNS,      // Not a protocol (no dissector): ID# 225 (OpenDNS)
    NDPI_PROTOCOL_PANDORA,      // Not a protocol: ID# 187 (Pandora)
    NDPI_PROTOCOL_PASTEBIN,     // Not a protocol: ID# 232 (Pastebin)
    NDPI_PROTOCOL_PINTEREST,    // Not a protocol: ID# 183 (Pinterest)
    NDPI_PROTOCOL_PLAYSTATION,  // Not a protocol (no dissector): ID# 231 (Playstation)
    NDPI_PROTOCOL_PLAYSTORE,    // Not a protocol: ID# 228 (PlayStore)
    NDPI_PROTOCOL_PLURALSIGHT,  // Not a protocol (no dissector): ID# 61 (Pluralsight)
    NDPI_PROTOCOL_PSIPHON,      // Not a protocol: ID# 303 (Psiphon)
    NDPI_PROTOCOL_REDDIT,       // Not a protocol: ID# 205 (Reddit)
    NDPI_PROTOCOL_SALESFORCE,   // Not a protocol: ID# 266 (Salesforce)
    NDPI_PROTOCOL_SHOWTIME,     // Not a protocol: ID# 321 (Showtime)
    NDPI_PROTOCOL_SIGNAL,       // Not a protocol (see SIGNAL_VOIP): ID# 39 (Signal)
    NDPI_PROTOCOL_SINA,         // Not a protocol (no dissector): ID# 200 (Sina(Weibo))
    NDPI_PROTOCOL_SIRIUSXMRADIO, // Not a protocol: ID# 328 (SiriusXMRadio)
    NDPI_PROTOCOL_SLACK,        // Not a protocol (no dissector): ID# 118 (Slack)
    NDPI_PROTOCOL_SNAPCHAT,     // Not a protocol (no dissector): ID# 199 (Snapchat)
    NDPI_PROTOCOL_SOFTETHER,    // Not a protocol (no dissector): ID# 290 (Softether)
    NDPI_PROTOCOL_SOUNDCLOUD,   // Not a protocol: ID# 234 (SoundCloud)
    NDPI_PROTOCOL_TENCENT,      // Not a protocol: ID# 285 (Tencent)
    NDPI_PROTOCOL_TENCENTVIDEO, // Not a protocol: ID# 324 (Tencentvideo)
    NDPI_PROTOCOL_TIDAL,        // Not a protocol: ID# 326 (Tidal)
    NDPI_PROTOCOL_TOR,          // Not a protocol (no dissector): ID# 163 (Tor)
    NDPI_PROTOCOL_TUENTI,       // Not a protocol: ID# 149 (Tuenti)
    NDPI_PROTOCOL_TUMBLR,       // Not a protocol: ID# 90 (Tumblr)
    NDPI_PROTOCOL_TUNEIN,       // Not a protocol: ID# 327 (TuneIn)
    NDPI_PROTOCOL_TUNNELBEAR,   // Not a protocol (no dissector): ID# 299 (TunnelBear)
    NDPI_PROTOCOL_TWITCH,       // Not a protocol (no dissector): ID# 195 (Twitch)
    NDPI_PROTOCOL_TWITTER,      // Not a protocol: ID# 120 (Twitter)
    NDPI_PROTOCOL_UBUNTUONE,    // Not a protocol: ID# 169 (UbuntuONE)
    NDPI_PROTOCOL_VEVO,         // Not a protocol: ID# 186 (Vevo)
    NDPI_PROTOCOL_VIMEO,        // Not a protocol: ID# 267 (Vimeo)
    NDPI_PROTOCOL_VUDU,         // Not a protocol: ID# 320 (Vudu)
    NDPI_PROTOCOL_WAZE,         // Not a protocol: ID# 135 (Waze)
    NDPI_PROTOCOL_WEBEX,        // Not a protocol (no dissector): ID# 141 (Webex)
    NDPI_PROTOCOL_WECHAT,       // Not a protocol (no dissector): ID# 197 (WeChat)
    NDPI_PROTOCOL_WHATSAPP_FILES, // Not a protocol: ID# 242 (WhatsAppFiles)
    NDPI_PROTOCOL_WIKIPEDIA,    // Not a protocol: ID# 176 (Wikipedia)
    NDPI_PROTOCOL_WINDOWS_UPDATE, // Not a protocol (no dissector): ID# 147 (WindowsUpdate)
    NDPI_PROTOCOL_YAHOO,        // Not a protocol: ID# 70 (Yahoo)
    NDPI_PROTOCOL_YOUTUBE,      // Not a protocol: ID# 124 (YouTube)
    NDPI_PROTOCOL_YOUTUBE_UPLOAD, // Not a protocol: ID# 136 (YouTubeUpload)
};

typedef vector<uint16_t> nd_ndpi_free_protos_t;

const nd_ndpi_free_protos_t nd_ndpi_free_protos = {
    NDPI_PROTOCOL_FREE_22,
    NDPI_PROTOCOL_FREE_25,
    NDPI_PROTOCOL_FREE_33,
    NDPI_PROTOCOL_FREE_34,
    NDPI_PROTOCOL_FREE_56,
    NDPI_PROTOCOL_FREE_57,
    NDPI_PROTOCOL_FREE_62,
    NDPI_PROTOCOL_FREE_98,
    NDPI_PROTOCOL_FREE_99,
    NDPI_PROTOCOL_FREE_107,
    NDPI_PROTOCOL_FREE_108,
};

typedef unordered_map<uint16_t, vector<pair<uint16_t, nd_proto_id_t>>> nd_ndpi_portmap_t;

const nd_ndpi_portmap_t nd_ndpi_portmap = {
    { NDPI_PROTOCOL_TLS, {
        { 53, ND_PROTO_DOT },
        { 443, ND_PROTO_HTTPS },
        { 563, ND_PROTO_NNTPS },
        { 853, ND_PROTO_DOT },
        { 465, ND_PROTO_MAIL_SMTPS },
        { 585, ND_PROTO_MAIL_IMAPS },
        { 587, ND_PROTO_MAIL_SMTPS },
        { 993, ND_PROTO_MAIL_IMAPS },
        { 995, ND_PROTO_MAIL_POPS },
        { 989, ND_PROTO_FTPS_DATA },
        { 990, ND_PROTO_FTPS },
        { 1883, ND_PROTO_MQTTS },
        { 5061, ND_PROTO_SIPS },
        { 6514, ND_PROTO_SYSLOGS },
        { 6697, ND_PROTO_IRCS },
        { 8883, ND_PROTO_MQTTS },
    } },
};

class ndFlow;
const nd_proto_id_t nd_ndpi_proto_find(uint16_t id, const ndFlow *flow);
const uint16_t nd_ndpi_proto_find(unsigned id);

#endif // _ND_PROTOS_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
