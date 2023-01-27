%define api.pure full
%locations
%param { yyscan_t scanner }

%code top {
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdexcept>
#include <cstring>
#include <map>
#include <list>
#include <vector>
#include <set>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <regex>
#include <mutex>
#include <bitset>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <errno.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#include "nd-risks.h"
#include "nd-serializer.h"
#include "nd-packet.h"
#include "nd-json.h"
#include "nd-util.h"
#include "nd-addr.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-apps.h"
#include "nd-category.h"
#include "nd-protos.h"
#include "nd-flow.h"

#include "nd-flow-parser.h"
#include "nd-flow-criteria.tab.hh"

extern "C" {
    #include "nd-flow-criteria.h"

    void yyerror(YYLTYPE *yyllocp, yyscan_t scanner, const char *message);
}

void yyerror(YYLTYPE *yyllocp, yyscan_t scanner, const char *message)
{
    throw string(message);
}

extern ndCategories *nd_categories;
extern ndDomains *nd_domains;
}

%code requires {
typedef void* yyscan_t;
}

%expect 4

%union
{
    char string[_NDFP_MAX_NAMELEN];

    bool bool_number;
    unsigned short us_number;
    unsigned long ul_number;

    bool bool_result;
}

%token FLOW_IP_PROTO FLOW_IP_VERSION FLOW_IP_NAT FLOW_VLAN_ID FLOW_OTHER_TYPE
%token FLOW_LOCAL_MAC FLOW_OTHER_MAC FLOW_LOCAL_IP FLOW_OTHER_IP
%token FLOW_LOCAL_PORT FLOW_OTHER_PORT
%token FLOW_TUNNEL_TYPE
%token FLOW_DETECTION_GUESSED
%token FLOW_DETECTION_UPDATED
%token FLOW_CATEGORY
%token FLOW_RISKS FLOW_NDPI_RISK_SCORE FLOW_NDPI_RISK_SCORE_CLIENT FLOW_NDPI_RISK_SCORE_SERVER
%token FLOW_DOMAIN_CATEGORY
%token FLOW_APPLICATION FLOW_APPLICATION_CATEGORY
%token FLOW_PROTOCOL FLOW_PROTOCOL_CATEGORY
%token FLOW_DETECTED_HOSTNAME FLOW_SSL_VERSION FLOW_SSL_CIPHER FLOW_ORIGIN
%token FLOW_CT_MARK

%token <us_number> FLOW_OTHER_UNKNOWN FLOW_OTHER_UNSUPPORTED FLOW_OTHER_LOCAL
%token <us_number> FLOW_OTHER_MULTICAST FLOW_OTHER_BROADCAST FLOW_OTHER_REMOTE
%token <us_number> FLOW_OTHER_ERROR

%token <us_number> FLOW_ORIGIN_LOCAL FLOW_ORIGIN_OTHER FLOW_ORIGIN_UNKNOWN

%token <us_number> FLOW_TUNNEL_NONE FLOW_TUNNEL_GTP

%token CMP_EQUAL CMP_NOTEQUAL CMP_GTHANEQUAL CMP_LTHANEQUAL BOOL_AND BOOL_OR

%token VALUE_ADDR_IPMASK
%token <bool_number> VALUE_TRUE VALUE_FALSE
%token <string> VALUE_ADDR_MAC VALUE_ADDR_IPV4 VALUE_ADDR_IPV6 VALUE_NAME VALUE_REGEX
%token <ul_number> VALUE_NUMBER

%type <us_number> value_other_type value_origin_type
%type <string> value_addr_ip
%type <us_number> value_tunnel_type

%type <bool_result> expr expr_ip_proto expr_ip_version expr_ip_nat expr_vlan_id expr_other_type
%type <bool_result> expr_local_mac expr_other_mac expr_local_ip expr_other_ip
%type <bool_result> expr_local_port expr_other_port
%type <bool_result> expr_tunnel_type expr_detection_guessed expr_detection_updated
%type <bool_result> expr_category
%type <bool_result> expr_risks expr_ndpi_risk_score expr_ndpi_risk_score_client expr_ndpi_risk_score_server
%type <bool_result> expr_app expr_app_id expr_app_name expr_app_category
%type <bool_result> expr_domain_category
%type <bool_result> expr_proto expr_proto_id expr_proto_name expr_proto_category
%type <bool_result> expr_detected_hostname expr_ssl_version expr_ssl_cipher
%type <bool_result> expr_origin expr_fwmark

%%

exprs:
    |
      exprs expr ';'
    ;

expr:
      expr_ip_proto
    | expr_ip_version
    | expr_ip_nat
    | expr_vlan_id
    | expr_other_type
    | expr_local_mac
    | expr_other_mac
    | expr_local_ip
    | expr_other_ip
    | expr_local_port
    | expr_other_port
    | expr_tunnel_type
    | expr_detection_guessed
    | expr_detection_updated
    | expr_category
    | expr_risks
    | expr_ndpi_risk_score
    | expr_ndpi_risk_score_client
    | expr_ndpi_risk_score_server
    | expr_app
    | expr_app_category
    | expr_domain_category
    | expr_proto
    | expr_proto_category
    | expr_detected_hostname
    | expr_ssl_version
    | expr_ssl_cipher
    | expr_origin
    | expr_fwmark
    | expr BOOL_OR expr {
        _NDFP_result = ($$ = ($1 || $3));
        _NDFP_debugf("OR (%d || %d == %d)\n", $1, $3, $$);
    }
    | expr BOOL_AND expr {
        _NDFP_result = ($$ = ($1 && $3));
        _NDFP_debugf("AND (%d && %d == %d)\n", $1, $3, $$);
    }
    | '(' expr ')' { _NDFP_result = ($$ = $2); }
    ;

expr_ip_proto:
      FLOW_IP_PROTO {
        _NDFP_result = ($$ = (_NDFP_flow->ip_protocol != 0));
        _NDFP_debugf(
            "IP Protocol is non-zero? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_IP_PROTO {
        _NDFP_result = ($$ = (_NDFP_flow->ip_protocol == 0));
        _NDFP_debugf("IP Protocol is zero? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_IP_PROTO CMP_EQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ip_protocol == $3));
        _NDFP_debugf("IP Protocol == %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_IP_PROTO CMP_NOTEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ip_protocol != $3));
        _NDFP_debugf("IP Protocol != %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_IP_PROTO CMP_GTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ip_protocol >= $3));
        _NDFP_debugf("IP Protocol >= %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_IP_PROTO CMP_LTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ip_protocol <= $3));
        _NDFP_debugf("IP Protocol <= %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_IP_PROTO '>' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ip_protocol > $3));
        _NDFP_debugf("IP Protocol > %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_IP_PROTO '<' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ip_protocol < $3));
        _NDFP_debugf("IP Protocol > %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_ip_version:
      FLOW_IP_VERSION CMP_EQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ip_version == $3));
        _NDFP_debugf("IP Version == %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_IP_VERSION CMP_NOTEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ip_version != $3));
        _NDFP_debugf("IP Version != %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_ip_nat:
      FLOW_IP_NAT {
        _NDFP_result = ($$ = (_NDFP_flow->flags.ip_nat.load() == true));
        _NDFP_debugf("IP NAT is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_IP_NAT {
        _NDFP_result = ($$ = (_NDFP_flow->flags.ip_nat.load() == false));
        _NDFP_debugf("IP NAT is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_IP_NAT CMP_EQUAL VALUE_TRUE {
        _NDFP_result = ($$ = (_NDFP_flow->flags.ip_nat.load() == true));
        _NDFP_debugf("IP NAT == true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_IP_NAT CMP_EQUAL VALUE_FALSE {
        _NDFP_result = ($$ = (_NDFP_flow->flags.ip_nat.load() == false));
        _NDFP_debugf("IP NAT == false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_IP_NAT CMP_NOTEQUAL VALUE_TRUE {
        _NDFP_result = ($$ = (_NDFP_flow->flags.ip_nat.load() != true));
        _NDFP_debugf("IP NAT != true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_IP_NAT CMP_NOTEQUAL VALUE_FALSE {
        _NDFP_result = ($$ = (_NDFP_flow->flags.ip_nat.load() != false));
        _NDFP_debugf("IP NAT != false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_vlan_id:
      FLOW_VLAN_ID {
        _NDFP_result = ($$ = (_NDFP_flow->vlan_id != 0));
        _NDFP_debugf("VLAN ID is non-zero? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_VLAN_ID {
        _NDFP_result = ($$ = (_NDFP_flow->vlan_id == 0));
        _NDFP_debugf("VLAN ID is zero? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_VLAN_ID CMP_EQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->vlan_id == $3));
        _NDFP_debugf("VLAN ID == %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_VLAN_ID CMP_NOTEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->vlan_id != $3));
        _NDFP_debugf("VLAN ID != %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_VLAN_ID CMP_GTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->vlan_id >= $3));
        _NDFP_debugf("VLAN ID >= %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_VLAN_ID CMP_LTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->vlan_id <= $3));
        _NDFP_debugf("VLAN ID <= %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_VLAN_ID '>' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->vlan_id > $3));
        _NDFP_debugf("VLAN ID > %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_VLAN_ID '<' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->vlan_id < $3));
        _NDFP_debugf("VLAN ID < %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_other_type:
      FLOW_OTHER_TYPE {
        _NDFP_result = ($$ = (
            _NDFP_flow->other_type != ndFlow::OTHER_UNKNOWN
        ));
        _NDFP_debugf("Other type known? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_OTHER_TYPE {
        _NDFP_result = ($$ = (
            _NDFP_flow->other_type == ndFlow::OTHER_UNKNOWN
        ));
        _NDFP_debugf("Other type unknown? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_OTHER_TYPE CMP_EQUAL value_other_type {
        switch ($3) {
        case _NDFP_OTHER_UNKNOWN:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_UNKNOWN
            );
            break;
        case _NDFP_OTHER_UNSUPPORTED:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_UNSUPPORTED
            );
            break;
        case _NDFP_OTHER_LOCAL:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_LOCAL
            );
            break;
        case _NDFP_OTHER_MULTICAST:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_MULTICAST
            );
            break;
        case _NDFP_OTHER_BROADCAST:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_BROADCAST
            );
            break;
        case _NDFP_OTHER_REMOTE:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_REMOTE
            );
            break;
        case _NDFP_OTHER_ERROR:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::OTHER_ERROR
            );
            break;
        default:
            _NDFP_result = false;
        }

        $$ = _NDFP_result;
        _NDFP_debugf("Other type == %hu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_OTHER_TYPE CMP_NOTEQUAL value_other_type {
        switch ($3) {
        case _NDFP_OTHER_UNKNOWN:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_UNKNOWN
            );
            break;
        case _NDFP_OTHER_UNSUPPORTED:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_UNSUPPORTED
            );
            break;
        case _NDFP_OTHER_LOCAL:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_LOCAL
            );
            break;
        case _NDFP_OTHER_MULTICAST:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_MULTICAST
            );
            break;
        case _NDFP_OTHER_BROADCAST:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_BROADCAST
            );
            break;
        case _NDFP_OTHER_REMOTE:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_REMOTE
            );
            break;
        case _NDFP_OTHER_ERROR:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::OTHER_ERROR
            );
            break;
        default:
            _NDFP_result = false;
        }

        $$ = _NDFP_result;
        _NDFP_debugf("Other type != %hu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

value_other_type:
      FLOW_OTHER_UNKNOWN { $$ = $1; }
    | FLOW_OTHER_UNSUPPORTED { $$ = $1; }
    | FLOW_OTHER_LOCAL { $$ = $1; }
    | FLOW_OTHER_MULTICAST { $$ = $1; }
    | FLOW_OTHER_BROADCAST { $$ = $1; }
    | FLOW_OTHER_REMOTE { $$ = $1; }
    | FLOW_OTHER_ERROR { $$ = $1; }
    ;

expr_local_mac:
      FLOW_LOCAL_MAC CMP_EQUAL VALUE_ADDR_MAC {
        _NDFP_result = ($$ = (
            strncasecmp(_NDFP_local_mac, $3, ND_STR_ETHALEN) == 0
        ));
        _NDFP_debugf("Local MAC == %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_LOCAL_MAC CMP_NOTEQUAL VALUE_ADDR_MAC {
        _NDFP_result = ($$ = (
            strncasecmp(_NDFP_local_mac, $3, ND_STR_ETHALEN) != 0
        ));
        _NDFP_debugf("Local MAC != %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_other_mac:
      FLOW_OTHER_MAC CMP_EQUAL VALUE_ADDR_MAC {
        _NDFP_result = ($$ = (
            strncasecmp(_NDFP_other_mac, $3, ND_STR_ETHALEN) == 0
        ));
        _NDFP_debugf("Other MAC == %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_OTHER_MAC CMP_NOTEQUAL VALUE_ADDR_MAC {
        _NDFP_result = ($$ = (
            strncasecmp(_NDFP_other_mac, $3, ND_STR_ETHALEN) != 0
        ));
        _NDFP_debugf("Other MAC != %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_local_ip:
      FLOW_LOCAL_IP CMP_EQUAL value_addr_ip {
        _NDFP_result = ($$ = (
            strncasecmp(_NDFP_local_ip, $3, INET6_ADDRSTRLEN) == 0
        ));
        _NDFP_debugf("Local IP == %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_LOCAL_IP CMP_NOTEQUAL value_addr_ip {
        _NDFP_result = ($$ = (
            strncasecmp(_NDFP_local_ip, $3, INET6_ADDRSTRLEN) != 0
        ));
        _NDFP_debugf("Local IP != %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_other_ip:
      FLOW_OTHER_IP CMP_EQUAL value_addr_ip {
        _NDFP_result = ($$ = (
            strncasecmp(_NDFP_other_ip, $3, INET6_ADDRSTRLEN) == 0
        ));
        _NDFP_debugf("Other IP == %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_OTHER_IP CMP_NOTEQUAL value_addr_ip {
        _NDFP_result = ($$ = (
            strncasecmp(_NDFP_other_ip, $3, INET6_ADDRSTRLEN) != 0
        ));
        _NDFP_debugf("Other IP != %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

value_addr_ip:
      VALUE_ADDR_IPV4 { strncpy($$, $1, _NDFP_MAX_NAMELEN); }
    | VALUE_ADDR_IPV6 { strncpy($$, $1, _NDFP_MAX_NAMELEN); }
    ;

expr_local_port:
      FLOW_LOCAL_PORT {
        _NDFP_result = ($$ = (_NDFP_local_port != 0));
        _NDFP_debugf("Local port is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_LOCAL_PORT {
        _NDFP_result = ($$ = (_NDFP_local_port == 0));
        _NDFP_debugf("Local port is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_LOCAL_PORT CMP_EQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_local_port == $3));
        _NDFP_debugf("Local port == %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_LOCAL_PORT CMP_NOTEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_local_port != $3));
        _NDFP_debugf("Local port != %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_LOCAL_PORT CMP_GTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_local_port >= $3));
        _NDFP_debugf("Local port >= %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_LOCAL_PORT CMP_LTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_local_port <= $3));
        _NDFP_debugf("Local port <= %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_LOCAL_PORT '>' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_local_port > $3));
        _NDFP_debugf("Local port > %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_LOCAL_PORT '<' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_local_port < $3));
        _NDFP_debugf("Local port > %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_other_port:
      FLOW_OTHER_PORT {
        _NDFP_result = ($$ = (_NDFP_other_port != 0));
        _NDFP_debugf("Other port is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_OTHER_PORT {
        _NDFP_result = ($$ = (_NDFP_other_port == 0));
        _NDFP_debugf("Other port is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_OTHER_PORT CMP_EQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_other_port == $3));
        _NDFP_debugf("Other port == %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_OTHER_PORT CMP_NOTEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_other_port != $3));
        _NDFP_debugf("Other port != %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_OTHER_PORT CMP_GTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_other_port >= $3));
        _NDFP_debugf("Other port >= %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_OTHER_PORT CMP_LTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_other_port <= $3));
        _NDFP_debugf("Other port <= %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_OTHER_PORT '>' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_other_port > $3));
        _NDFP_debugf("Other port > %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_OTHER_PORT '<' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_other_port < $3));
        _NDFP_debugf("Other port > %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_tunnel_type:
      FLOW_TUNNEL_TYPE {
        _NDFP_result = ($$ = (
            _NDFP_flow->tunnel_type != ndFlow::TUNNEL_NONE
        ));
        _NDFP_debugf("Tunnel type set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_TUNNEL_TYPE {
        _NDFP_result = ($$ = (
            _NDFP_flow->tunnel_type == ndFlow::TUNNEL_NONE
        ));
        _NDFP_debugf("Tunnel type is none? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_TUNNEL_TYPE CMP_EQUAL value_tunnel_type {
        switch ($3) {
        case _NDFP_TUNNEL_NONE:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::TUNNEL_NONE
            );
            break;
        case _NDFP_TUNNEL_GTP:
            _NDFP_result = (
                _NDFP_flow->other_type == ndFlow::TUNNEL_GTP
            );
            break;
        default:
            _NDFP_result = false;
        }

        $$ = _NDFP_result;
        _NDFP_debugf("Tunnel type == %hu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_TUNNEL_TYPE CMP_NOTEQUAL value_tunnel_type {
        switch ($3) {
        case _NDFP_TUNNEL_NONE:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::TUNNEL_NONE
            );
            break;
        case _NDFP_TUNNEL_GTP:
            _NDFP_result = (
                _NDFP_flow->other_type != ndFlow::TUNNEL_GTP
            );
            break;
        default:
            _NDFP_result = false;
        }

        $$ = _NDFP_result;
        _NDFP_debugf("Tunnel type != %hu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

value_tunnel_type:
      FLOW_TUNNEL_NONE { $$ = $1; }
    | FLOW_TUNNEL_GTP { $$ = $1; }

expr_detection_guessed:
      FLOW_DETECTION_GUESSED {
        _NDFP_result = ($$ = (_NDFP_flow->flags.detection_guessed.load()));
        _NDFP_debugf("Detection was guessed? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!'  FLOW_DETECTION_GUESSED {
        _NDFP_result = ($$ = !(_NDFP_flow->flags.detection_guessed.load()));
        _NDFP_debugf(
            "Detection was not guessed? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
    | FLOW_DETECTION_GUESSED CMP_EQUAL VALUE_TRUE {
        _NDFP_result = ($$ = (
            _NDFP_flow->flags.detection_guessed.load() == true
        ));
        _NDFP_debugf(
            "Detection guessed == true? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
    | FLOW_DETECTION_GUESSED CMP_EQUAL VALUE_FALSE {
        _NDFP_result = ($$ = (
            _NDFP_flow->flags.detection_guessed.load() == false
        ));
        _NDFP_debugf(
            "Detection guessed == false? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
    | FLOW_DETECTION_GUESSED CMP_NOTEQUAL VALUE_TRUE {
        _NDFP_result = ($$ = (
            _NDFP_flow->flags.detection_guessed.load() != true
        ));
        _NDFP_debugf(
            "Detection guessed != true? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
    | FLOW_DETECTION_GUESSED CMP_NOTEQUAL VALUE_FALSE {
        _NDFP_result = ($$ = (
            _NDFP_flow->flags.detection_guessed.load() != false
        ));
        _NDFP_debugf(
            "Detection guessed != false? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
    ;

expr_detection_updated:
      FLOW_DETECTION_UPDATED {
        _NDFP_result = ($$ = (_NDFP_flow->flags.detection_updated.load()));
        _NDFP_debugf("Detection was updated? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!'  FLOW_DETECTION_UPDATED {
        _NDFP_result = ($$ = !(_NDFP_flow->flags.detection_updated.load()));
        _NDFP_debugf(
            "Detection was not updated? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
    | FLOW_DETECTION_UPDATED CMP_EQUAL VALUE_TRUE {
        _NDFP_result = ($$ = (
            _NDFP_flow->flags.detection_updated.load() == true
        ));
        _NDFP_debugf(
            "Detection updated == true? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
    | FLOW_DETECTION_UPDATED CMP_EQUAL VALUE_FALSE {
        _NDFP_result = ($$ = (
            _NDFP_flow->flags.detection_updated.load() == false
        ));
        _NDFP_debugf(
            "Detection updated == false? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
    | FLOW_DETECTION_UPDATED CMP_NOTEQUAL VALUE_TRUE {
        _NDFP_result = ($$ = (
            _NDFP_flow->flags.detection_updated.load() != true
        ));
        _NDFP_debugf(
            "Detection updated != true? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
    | FLOW_DETECTION_UPDATED CMP_NOTEQUAL VALUE_FALSE {
        _NDFP_result = ($$ = (
            _NDFP_flow->flags.detection_updated.load() != false
        ));
        _NDFP_debugf(
            "Detection updated != false? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
    ;

expr_app:
      FLOW_APPLICATION {
        _NDFP_result = ($$ = (
            _NDFP_flow->detected_application != 0
        ));
        _NDFP_debugf("Application detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_APPLICATION {
        _NDFP_result = ($$ = (
            _NDFP_flow->detected_application == 0
        ));
        _NDFP_debugf(
            "Application not detected? %s\n", (_NDFP_result) ? "yes" : "no"
        );
    }
    | expr_app_id
    | expr_app_name

expr_app_id:
      FLOW_APPLICATION CMP_EQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = false);
        if ($3 == _NDFP_flow->detected_application)
            _NDFP_result = ($$ = true);

        _NDFP_debugf(
            "Application ID == %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no"
        );
    }
    | FLOW_APPLICATION CMP_NOTEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = true);
        if ($3 == _NDFP_flow->detected_application)
            _NDFP_result = ($$ = false);

        _NDFP_debugf(
            "Application ID != %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no"
        );
    }
    ;

expr_app_name:
      FLOW_APPLICATION CMP_EQUAL VALUE_NAME {
        _NDFP_result = ($$ = false);
        if (_NDFP_flow->detected_application_name != NULL) {

            size_t p;
            string search($3);
            string app(_NDFP_flow->detected_application_name);

            while ((p = search.find_first_of("'")) != string::npos)
                search.erase(p, 1);

            if (strncasecmp(
                app.c_str(), search.c_str(), _NDFP_MAX_NAMELEN) == 0) {
                _NDFP_result = ($$ = true);
            }
            else if ((p = app.find_first_of(".")) != string::npos && strncasecmp(
                app.substr(p + 1).c_str(), search.c_str(), _NDFP_MAX_NAMELEN) == 0) {
                _NDFP_result = ($$ = true);
            }
        }

        _NDFP_debugf(
            "Application name == %s? %s\n", $3, (_NDFP_result) ? "yes" : "no"
        );
    }
    | FLOW_APPLICATION CMP_NOTEQUAL VALUE_NAME {
        _NDFP_result = ($$ = true);
        if (_NDFP_flow->detected_application_name != NULL) {

            size_t p;
            string search($3);
            string app(_NDFP_flow->detected_application_name);

            while ((p = search.find_first_of("'")) != string::npos)
                search.erase(p, 1);

            if (strncasecmp(
                app.c_str(), search.c_str(), _NDFP_MAX_NAMELEN) == 0) {
                _NDFP_result = ($$ = false);
            }
            else if ((p = app.find_first_of(".")) != string::npos && strncasecmp(
                app.substr(p + 1).c_str(), search.c_str(), _NDFP_MAX_NAMELEN) == 0) {
                _NDFP_result = ($$ = false);
            }
        }

        _NDFP_debugf(
            "Application name != %s? %s\n", $3, (_NDFP_result) ? "yes" : "no"
        );
    }
    ;

expr_category:
      FLOW_CATEGORY CMP_EQUAL VALUE_NAME {
        size_t p;
        string category($3);

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            $$ = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_APP, category) == _NDFP_flow->category.application
            )
        );

        if (! _NDFP_result) {
            _NDFP_result = (
                $$ = (
                    nd_categories->LookupTag(
                        ndCAT_TYPE_APP, category) == _NDFP_flow->category.domain
                )
            );
        }

        _NDFP_debugf("App/domain category == %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_CATEGORY CMP_NOTEQUAL VALUE_NAME {
        size_t p;
        string category($3);

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            $$ = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_APP, category) != _NDFP_flow->category.application
            )
        );

        if (! _NDFP_result) {
            _NDFP_result = (
                $$ = (
                    nd_categories->LookupTag(
                        ndCAT_TYPE_APP, category) != _NDFP_flow->category.domain
                )
            );
        }

        _NDFP_debugf("App/domain category != %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_risks:
      FLOW_RISKS {
        _NDFP_result = ($$ = (_NDFP_flow->risks.size() != 0));
        _NDFP_debugf("Risks detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_RISKS {
        _NDFP_result = ($$ = (_NDFP_flow->risks.size() == 0));
        _NDFP_debugf("Risks not detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_RISKS CMP_EQUAL VALUE_NAME {
        size_t p;
        string risk($3);

        while ((p = risk.find_first_of("'")) != string::npos)
            risk.erase(p, 1);

        nd_risk_id_t id = nd_risk_lookup(risk);

        _NDFP_result = false;
        for (auto &i : _NDFP_flow->risks) {
            if (i != id) continue;
            _NDFP_result = true;
            break;
        }

        _NDFP_debugf("Risks == %s %s\n", $3, risk.c_str(), (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_RISKS CMP_NOTEQUAL VALUE_NAME {
        size_t p;
        string risk($3);

        while ((p = risk.find_first_of("'")) != string::npos)
            risk.erase(p, 1);

        nd_risk_id_t id = nd_risk_lookup(risk);

        _NDFP_result = false;
        for (auto &i : _NDFP_flow->risks) {
            if (i != id) continue;
            _NDFP_result = true;
            break;
        }

        _NDFP_result = !_NDFP_result;
        _NDFP_debugf("Risks != %s %s\n", $3, risk.c_str(), (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_ndpi_risk_score:
      FLOW_NDPI_RISK_SCORE {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score != 0));
        _NDFP_debugf("nDPI risk score is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_NDPI_RISK_SCORE {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score == 0));
        _NDFP_debugf("nDPI risk score is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE CMP_EQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score == $3));
        _NDFP_debugf("nDPI risk score == %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE CMP_NOTEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score != $3));
        _NDFP_debugf("nDPI risk score != %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE CMP_GTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score >= $3));
        _NDFP_debugf("nDPI risk score >= %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE CMP_LTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score <= $3));
        _NDFP_debugf("nDPI risk score <= %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE '>' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score > $3));
        _NDFP_debugf("nDPI risk score > %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE '<' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score < $3));
        _NDFP_debugf("nDPI risk score > %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_ndpi_risk_score_client:
      FLOW_NDPI_RISK_SCORE_CLIENT {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_client != 0));
        _NDFP_debugf("nDPI risk client score is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_NDPI_RISK_SCORE_CLIENT {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_client == 0));
        _NDFP_debugf("nDPI risk client score is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE_CLIENT CMP_EQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_client == $3));
        _NDFP_debugf("nDPI risk client score == %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE_CLIENT CMP_NOTEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_client != $3));
        _NDFP_debugf("nDPI risk client score != %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE_CLIENT CMP_GTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_client >= $3));
        _NDFP_debugf("nDPI risk client score >= %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE_CLIENT CMP_LTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_client <= $3));
        _NDFP_debugf("nDPI risk client score <= %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE_CLIENT '>' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_client > $3));
        _NDFP_debugf("nDPI risk client score > %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE_CLIENT '<' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_client < $3));
        _NDFP_debugf("nDPI risk client score > %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_ndpi_risk_score_server:
      FLOW_NDPI_RISK_SCORE_SERVER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_server != 0));
        _NDFP_debugf("nDPI risk server score is true? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_NDPI_RISK_SCORE_SERVER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_server == 0));
        _NDFP_debugf("nDPI risk server score is false? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE_SERVER CMP_EQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_server == $3));
        _NDFP_debugf("nDPI risk server score == %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE_SERVER CMP_NOTEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_server != $3));
        _NDFP_debugf("nDPI risk server score != %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE_SERVER CMP_GTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_server >= $3));
        _NDFP_debugf("nDPI risk server score >= %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE_SERVER CMP_LTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_server <= $3));
        _NDFP_debugf("nDPI risk server score <= %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE_SERVER '>' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_server > $3));
        _NDFP_debugf("nDPI risk server score > %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_NDPI_RISK_SCORE_SERVER '<' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ndpi_risk_score_server < $3));
        _NDFP_debugf("nDPI risk server score > %lu %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_app_category:
      FLOW_APPLICATION_CATEGORY CMP_EQUAL VALUE_NAME {
        size_t p;
        string category($3);

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            $$ = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_APP, category) == _NDFP_flow->category.application
            )
        );

        _NDFP_debugf("App category == %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_APPLICATION_CATEGORY CMP_NOTEQUAL VALUE_NAME {
        size_t p;
        string category($3);

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            $$ = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_APP, category) != _NDFP_flow->category.application
            )
        );

        _NDFP_debugf("App category != %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_domain_category:
      FLOW_DOMAIN_CATEGORY CMP_EQUAL VALUE_NAME {
        size_t p;
        string category($3);

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            $$ = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_APP, category) == _NDFP_flow->category.domain
            )
        );

        _NDFP_debugf("Domain category == %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_DOMAIN_CATEGORY CMP_NOTEQUAL VALUE_NAME {
        size_t p;
        string category($3);

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            $$ = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_APP, category) != _NDFP_flow->category.domain
            )
        );

        _NDFP_debugf("Domain category != %s? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_proto:
      FLOW_PROTOCOL {
        _NDFP_result = ($$ = (
            _NDFP_flow->detected_protocol != 0
        ));
        _NDFP_debugf("Protocol detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_PROTOCOL {
        _NDFP_result = ($$ = (
            _NDFP_flow->detected_protocol == 0
        ));
        _NDFP_debugf("Protocol not detected? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | expr_proto_id
    | expr_proto_name

expr_proto_id:
      FLOW_PROTOCOL CMP_EQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (
            _NDFP_flow->detected_protocol == $3
        ));
        _NDFP_debugf("Protocol ID == %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_PROTOCOL CMP_NOTEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (
            _NDFP_flow->detected_protocol != $3
        ));
        _NDFP_debugf("Protocol ID != %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_proto_name:
      FLOW_PROTOCOL CMP_EQUAL VALUE_NAME {
        _NDFP_result = ($$ = false);
        if (_NDFP_flow->detected_protocol_name != NULL) {

            size_t p;
            string search($3);

            while ((p = search.find_first_of("'")) != string::npos)
                search.erase(p, 1);

            _NDFP_result = ($$ = (strncasecmp(
                _NDFP_flow->detected_protocol_name, search.c_str(), _NDFP_MAX_NAMELEN
            ) == 0));
        }

        _NDFP_debugf(
            "Protocol name == %s? %s\n", $3, (_NDFP_result) ? "yes" : "no"
        );
    }
    | FLOW_PROTOCOL CMP_NOTEQUAL VALUE_NAME {
        _NDFP_result = ($$ = true);
        if (_NDFP_flow->detected_protocol_name != NULL) {

            size_t p;
            string search($3);

            while ((p = search.find_first_of("'")) != string::npos)
                search.erase(p, 1);

            _NDFP_result = ($$ = (strncasecmp(
                _NDFP_flow->detected_protocol_name, search.c_str(), _NDFP_MAX_NAMELEN
            )));
        }
        _NDFP_debugf(
            "Protocol name != %s? %s\n", $3, (_NDFP_result) ? "yes" : "no"
        );
    }
    ;

expr_proto_category:
      FLOW_PROTOCOL_CATEGORY CMP_EQUAL VALUE_NAME {
        size_t p;
        string category($3);

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            $$ = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_PROTO, category) == _NDFP_flow->category.protocol
            )
        );

        _NDFP_debugf("Protocol category == %s? %s\n",
            $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_PROTOCOL_CATEGORY CMP_NOTEQUAL VALUE_NAME {
        size_t p;
        string category($3);

        while ((p = category.find_first_of("'")) != string::npos)
            category.erase(p, 1);

        _NDFP_result = (
            $$ = (
                nd_categories->LookupTag(
                    ndCAT_TYPE_PROTO, category) != _NDFP_flow->category.protocol
            )
        );

        _NDFP_debugf("Protocol category != %s? %s\n",
            $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_detected_hostname:
      FLOW_DETECTED_HOSTNAME {
        _NDFP_result = ($$ = (
            _NDFP_flow->host_server_name[0] != '\0'
        ));
        _NDFP_debugf("Application hostname detected? %s\n",
            (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_DETECTED_HOSTNAME {
        _NDFP_result = ($$ = (
            _NDFP_flow->host_server_name[0] == '\0'
        ));
        _NDFP_debugf("Application hostname not detected? %s\n",
            (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_DETECTED_HOSTNAME CMP_EQUAL VALUE_NAME {
        _NDFP_result = ($$ = false);
        if (_NDFP_flow->host_server_name[0] != '\0') {
            size_t p;
            string search($3);

            while ((p = search.find_first_of("'")) != string::npos)
                search.erase(p, 1);

            if (strncasecmp(search.c_str(),
                _NDFP_flow->host_server_name, _NDFP_MAX_NAMELEN) == 0) {
                _NDFP_result = ($$ = true);
            }
        }

        _NDFP_debugf("Detected hostname == %s? %s\n",
            $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_DETECTED_HOSTNAME CMP_NOTEQUAL VALUE_NAME {
        _NDFP_result = ($$ = true);
        if (_NDFP_flow->host_server_name[0] != '\0') {
            size_t p;
            string search($3);

            while ((p = search.find_first_of("'")) != string::npos)
                search.erase(p, 1);

            if (strncasecmp(search.c_str(),
                _NDFP_flow->host_server_name, _NDFP_MAX_NAMELEN) == 0) {
                _NDFP_result = ($$ = false);
            }
        }

        _NDFP_debugf("Detected hostname != %s? %s\n",
            $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_DETECTED_HOSTNAME CMP_EQUAL VALUE_REGEX {
        _NDFP_result = ($$ = false);
#if HAVE_WORKING_REGEX
        if (_NDFP_flow->host_server_name[0] != '\0') {
            size_t p;
            string rx($3);

            while ((p = rx.find_first_of("'")) != string::npos)
                rx.erase(p, 1);
            while ((p = rx.find_first_of(":")) != string::npos)
                rx.erase(0, p);

            try {
                // XXX: Unfortunately we're going to compile this everytime...
                regex re(
                    rx,
                    regex_constants::icase |
                    regex_constants::optimize |
                    regex_constants::extended
                );

                cmatch match;
                _NDFP_result = ($$ = regex_search(
                    _NDFP_flow->host_server_name, match, re
                ));
            } catch (regex_error &e) {
                nd_printf("WARNING: Error compiling regex: %s: %d\n",
                    rx.c_str(), e.code());
            }
        }

        _NDFP_debugf("Detected hostname == %s? %s\n",
            $3, (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_debugf("Detected hostname == %s? Broken regex support.\n", $3);
#endif
    }
    | FLOW_DETECTED_HOSTNAME CMP_NOTEQUAL VALUE_REGEX {
        _NDFP_result = ($$ = true);

        _NDFP_debugf("Detected hostname != %s? %s\n",
            $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_fwmark:
      FLOW_CT_MARK {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ($$ = (_NDFP_flow->ct_mark != 0));
        _NDFP_debugf("FWMARK set? %s\n", (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ($$ = (false));
#endif
    }
    | '!' FLOW_CT_MARK {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ($$ = (_NDFP_flow->ct_mark == 0));
        _NDFP_debugf("FWMARK not set? %s\n", (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ($$ = (false));
#endif
    }
    | FLOW_CT_MARK CMP_EQUAL VALUE_NUMBER {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ($$ = (_NDFP_flow->ct_mark == $3));
        _NDFP_debugf("FWMARK == %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ($$ = (false));
#endif
    }
    | FLOW_CT_MARK CMP_NOTEQUAL VALUE_NUMBER {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ($$ = (_NDFP_flow->ct_mark != $3));
        _NDFP_debugf("FWMARK != %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ($$ = (false));
#endif
    }
    | FLOW_CT_MARK CMP_GTHANEQUAL VALUE_NUMBER {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ($$ = (_NDFP_flow->ct_mark >= $3));
        _NDFP_debugf("FWMARK >= %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ($$ = (false));
#endif
    }
    | FLOW_CT_MARK CMP_LTHANEQUAL VALUE_NUMBER {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ($$ = (_NDFP_flow->ct_mark <= $3));
        _NDFP_debugf("FWMARK <= %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ($$ = (false));
#endif
    }
    | FLOW_CT_MARK '>' VALUE_NUMBER {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ($$ = (_NDFP_flow->ct_mark > $3));
        _NDFP_debugf("FWMARK > %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ($$ = (false));
#endif
    }
    | FLOW_CT_MARK '<' VALUE_NUMBER {
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        _NDFP_result = ($$ = (_NDFP_flow->ct_mark < $3));
        _NDFP_debugf("FWMARK < %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
#else
        _NDFP_result = ($$ = (false));
#endif
    }
    ;

expr_ssl_version:
      FLOW_SSL_VERSION {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.version != 0));
        _NDFP_debugf("SSL version set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_SSL_VERSION {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.version == 0));
        _NDFP_debugf("SSL version not set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_SSL_VERSION CMP_EQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.version == $3));
        _NDFP_debugf("SSL version == %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_SSL_VERSION CMP_NOTEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.version != $3));
        _NDFP_debugf("SSL version != %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_SSL_VERSION CMP_GTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.version >= $3));
        _NDFP_debugf("SSL version >= %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_SSL_VERSION CMP_LTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.version <= $3));
        _NDFP_debugf("SSL version <= %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_SSL_VERSION '>' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.version > $3));
        _NDFP_debugf("SSL version > %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_SSL_VERSION '<' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.version < $3));
        _NDFP_debugf("SSL version < %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_ssl_cipher:
      FLOW_SSL_CIPHER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.cipher_suite != 0));
        _NDFP_debugf("SSL cipher suite set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_SSL_CIPHER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.cipher_suite == 0));
        _NDFP_debugf("SSL cipher suite not set? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_SSL_CIPHER CMP_EQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.cipher_suite == $3));
        _NDFP_debugf("SSL cipher suite == %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_SSL_CIPHER CMP_NOTEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.cipher_suite != $3));
        _NDFP_debugf("SSL cipher suite != %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_SSL_CIPHER CMP_GTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.cipher_suite >= $3));
        _NDFP_debugf("SSL cipher suite >= %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_SSL_CIPHER CMP_LTHANEQUAL VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.cipher_suite <= $3));
        _NDFP_debugf("SSL cipher suite <= %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_SSL_CIPHER '>' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.cipher_suite > $3));
        _NDFP_debugf("SSL cipher suite > %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_SSL_CIPHER '<' VALUE_NUMBER {
        _NDFP_result = ($$ = (_NDFP_flow->ssl.cipher_suite < $3));
        _NDFP_debugf("SSL cipher suite < %lu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

expr_origin:
      FLOW_ORIGIN {
        _NDFP_result = ($$ = (_NDFP_origin != _NDFP_ORIGIN_UNKNOWN));
        _NDFP_debugf("Flow origin known? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | '!' FLOW_ORIGIN {
        _NDFP_result = ($$ = (_NDFP_origin == _NDFP_ORIGIN_UNKNOWN));
        _NDFP_debugf("Flow origin unknown? %s\n", (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_ORIGIN CMP_EQUAL value_origin_type {
        _NDFP_result = ($$ = (_NDFP_origin == $3));
        _NDFP_debugf("Flow origin == %hu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    | FLOW_ORIGIN CMP_NOTEQUAL value_origin_type {
        _NDFP_result = ($$ = (_NDFP_origin != $3));
        _NDFP_debugf("Flow origin != %hu? %s\n", $3, (_NDFP_result) ? "yes" : "no");
    }
    ;

value_origin_type:
      FLOW_ORIGIN_LOCAL { $$ = $1; }
    | FLOW_ORIGIN_OTHER { $$ = $1; }
    | FLOW_ORIGIN_UNKNOWN { $$ = $1; }
    ;
%%

ndFlowParser::ndFlowParser()
    : flow(NULL), local_mac{}, other_mac{},
    local_ip(NULL), other_ip(NULL), local_port(0), other_port(0),
    origin(0), expr_result(false), scanner(NULL)
{
    yyscan_t scanner;
    yylex_init_extra((void *)this, &scanner);

    if (scanner == NULL)
        throw string("Error creating scanner context");

    this->scanner = (void *)scanner;
}

ndFlowParser::~ndFlowParser()
{
    yylex_destroy((yyscan_t)scanner);
}

bool ndFlowParser::Parse(const ndFlow *flow, const string &expr)
{
    this->flow = flow;
    expr_result = false;

    switch (flow->lower_map) {
    case ndFlow::LOWER_LOCAL:
        local_mac = flow->lower_mac.GetString().c_str();
        other_mac = flow->upper_mac.GetString().c_str();

        local_ip = flow->lower_addr.GetString().c_str();
        other_ip = flow->upper_addr.GetString().c_str();

        local_port = flow->lower_addr.GetPort();
        other_port = flow->upper_addr.GetPort();

        switch (flow->origin) {
        case ndFlow::ORIGIN_LOWER:
            origin = _NDFP_ORIGIN_LOCAL;
            break;
        case ndFlow::ORIGIN_UPPER:
            origin = _NDFP_ORIGIN_OTHER;
            break;
        default:
            origin = _NDFP_ORIGIN_UNKNOWN;
        }
        break;
    case ndFlow::LOWER_OTHER:
        local_mac = flow->upper_mac.GetString().c_str();
        other_mac = flow->lower_mac.GetString().c_str();

        local_ip = flow->upper_addr.GetString().c_str();
        other_ip = flow->lower_addr.GetString().c_str();

        local_port = flow->upper_addr.GetPort();
        other_port = flow->lower_addr.GetPort();

        switch (flow->origin) {
        case ndFlow::ORIGIN_LOWER:
            origin = _NDFP_ORIGIN_OTHER;
            break;
        case ndFlow::ORIGIN_UPPER:
            origin = _NDFP_ORIGIN_LOCAL;
            break;
        default:
            origin = _NDFP_ORIGIN_UNKNOWN;
        }
        break;
    default:
        //nd_dprintf("Bad lower map: %u\n", flow->lower_map);
        return false;
    }

    YY_BUFFER_STATE flow_expr_scan_buffer;
    flow_expr_scan_buffer = yy_scan_bytes(
        expr.c_str(), expr.size(), (yyscan_t)scanner
    );

    if (flow_expr_scan_buffer == NULL)
        throw string("Error allocating flow expression scan buffer");

    yy_switch_to_buffer(flow_expr_scan_buffer, (yyscan_t)scanner);

    int rc = 0;

    try {
        rc = yyparse((yyscan_t)scanner);
    } catch (...) {
        yy_delete_buffer(flow_expr_scan_buffer, scanner);
        throw;
    }

    yy_delete_buffer(flow_expr_scan_buffer, scanner);

    return (rc == 0) ? expr_result : false;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
