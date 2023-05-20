%option noinput nounput noyywrap 8bit nodefault
%option yylineno
%option reentrant bison-bridge bison-locations
%option header-file="nd-flow-criteria.h"

%{
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

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "nd-flow-parser.h"
#include "nd-flow-parser.hpp"
%}

%%
ip_protocol             return FLOW_IP_PROTO;
ip_version              return FLOW_IP_VERSION;
ip_nat                  return FLOW_IP_NAT;
vlan_id                 return FLOW_VLAN_ID;
other_type              return FLOW_OTHER_TYPE;
other_unknown           yylval->us_number = _NDFP_OTHER_UNKNOWN; return FLOW_OTHER_UNKNOWN;
other_unsupported       yylval->us_number = _NDFP_OTHER_UNSUPPORTED; return FLOW_OTHER_UNSUPPORTED;
other_local             yylval->us_number = _NDFP_OTHER_LOCAL; return FLOW_OTHER_LOCAL;
other_multicast         yylval->us_number = _NDFP_OTHER_MULTICAST; return FLOW_OTHER_MULTICAST;
other_broadcast         yylval->us_number = _NDFP_OTHER_BROADCAST; return FLOW_OTHER_BROADCAST;
other_remote            yylval->us_number = _NDFP_OTHER_REMOTE; return FLOW_OTHER_REMOTE;
other_error             yylval->us_number = _NDFP_OTHER_ERROR; return FLOW_OTHER_ERROR;
local_mac               return FLOW_LOCAL_MAC;
other_mac               return FLOW_OTHER_MAC;
local_ip                return FLOW_LOCAL_IP;
other_ip                return FLOW_OTHER_IP;
local_port              return FLOW_LOCAL_PORT;
other_port              return FLOW_OTHER_PORT;
tunnel_type             return FLOW_TUNNEL_TYPE;
tunnel_none             yylval->us_number = _NDFP_TUNNEL_NONE; return FLOW_TUNNEL_NONE;
tunnel_gtp              yylval->us_number = _NDFP_TUNNEL_GTP; return FLOW_TUNNEL_GTP;
detection_guessed       return FLOW_DETECTION_GUESSED;
detection_updated       return FLOW_DETECTION_UPDATED;
app                     return FLOW_APPLICATION;
application             return FLOW_APPLICATION;
application_id          return FLOW_APPLICATION;
app_id                  return FLOW_APPLICATION;
cat                     return FLOW_CATEGORY;
category                return FLOW_CATEGORY;
risks                   return FLOW_RISKS;
ndpi_risk_score         return FLOW_NDPI_RISK_SCORE;
ndpi_risk_client        return FLOW_NDPI_RISK_SCORE_CLIENT;
ndpi_risk_server        return FLOW_NDPI_RISK_SCORE_SERVER;
application_category    return FLOW_APPLICATION_CATEGORY;
app_category            return FLOW_APPLICATION_CATEGORY;
domain_category         return FLOW_DOMAIN_CATEGORY;
dom_category            return FLOW_DOMAIN_CATEGORY;
protocol                return FLOW_PROTOCOL;
proto                   return FLOW_PROTOCOL;
protocol_id             return FLOW_PROTOCOL;
proto_id                return FLOW_PROTOCOL;
protocol_category       return FLOW_PROTOCOL_CATEGORY;
proto_category          return FLOW_PROTOCOL_CATEGORY;
detected_hostname       return FLOW_DETECTED_HOSTNAME;
ssl_version             return FLOW_SSL_VERSION;
ssl_cipher              return FLOW_SSL_CIPHER;
origin                  return FLOW_ORIGIN;
origin_local            yylval->us_number = _NDFP_ORIGIN_LOCAL; return FLOW_ORIGIN_LOCAL;
origin_other            yylval->us_number = _NDFP_ORIGIN_OTHER; return FLOW_ORIGIN_OTHER;
origin_unknown          yylval->us_number = _NDFP_ORIGIN_UNKNOWN; return FLOW_ORIGIN_UNKNOWN;
fwmark                  return FLOW_CT_MARK;
[t|T][r|R][u|U][e|E]    yylval->bool_number=true; return VALUE_TRUE;
[f|F][a|A][l|L][s|S][e|E] yylval->bool_number=false; return VALUE_FALSE;
[a-fA-F0-9]{2}[:]{1}[a-fA-F0-9]{2}[:]{1}[a-fA-F0-9]{2}[:]{1}[a-fA-F0-9]{2}[:]{1}[a-fA-F0-9]{2}[:]{1}[a-fA-F0-9]{2} strncpy(yylval->string, yytext, _NDFP_MAX_NAMELEN); return VALUE_ADDR_MAC;
[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} strncpy(yylval->string, yytext, _NDFP_MAX_NAMELEN); return VALUE_ADDR_IPV4;
::1                     strncpy(yylval->string, yytext, _NDFP_MAX_NAMELEN); return VALUE_ADDR_IPV6;
[a-fA-F0-9]{4}[:]{1,2}[a-fA-F0-9:]* strncpy(yylval->string, yytext, _NDFP_MAX_NAMELEN); return VALUE_ADDR_IPV6;
\/[0-9]+                return VALUE_ADDR_IPMASK;
\'[a-zA-Z0-9][a-zA-Z0-9:\/\._+() -]+\' strncpy(yylval->string, yytext, _NDFP_MAX_NAMELEN); return VALUE_NAME;
\'rx:.*\'               strncpy(yylval->string, yytext, _NDFP_MAX_NAMELEN); return VALUE_REGEX;
0x[a-fA-F0-9]+          yylval->ul_number=(unsigned long)strtold(yytext, NULL); return VALUE_NUMBER;
[0-9]+                  yylval->ul_number=(unsigned long)strtold(yytext, NULL); return VALUE_NUMBER;
==                      return CMP_EQUAL;
!=                      return CMP_NOTEQUAL;
\>=                     return CMP_GTHANEQUAL;
\<=                     return CMP_LTHANEQUAL;
&&                      return BOOL_AND;
[a|A][n|N][d|D]         return BOOL_AND;
\|\|                    return BOOL_OR;
[o|O][r|R]              return BOOL_OR;
[ \t\n]+                /* Skip whitespace */
.                       return (int)yytext[0];
%%

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
