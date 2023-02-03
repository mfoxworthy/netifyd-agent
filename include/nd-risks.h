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

#ifndef _ND_RISKS_H
#define _ND_RISKS_H

typedef enum {
    ND_RISK_NONE                                    = 0,
    ND_RISK_ANONYMOUS_SUBSCRIBER                    = 1,
    ND_RISK_BINARY_APPLICATION_TRANSFER             = 2,
    ND_RISK_CLEAR_TEXT_CREDENTIALS                  = 3,
    ND_RISK_DESKTOP_OR_FILE_SHARING_SESSION         = 4,
    ND_RISK_DNS_FRAGMENTED                          = 5,
    ND_RISK_DNS_LARGE_PACKET                        = 6,
    ND_RISK_DNS_SUSPICIOUS_TRAFFIC                  = 7,
    ND_RISK_ERROR_CODE_DETECTED                     = 8,
    ND_RISK_HTTP_CRAWLER_BOT                        = 9,
    ND_RISK_HTTP_NUMERIC_IP_HOST                    = 10,
    ND_RISK_HTTP_SUSPICIOUS_CONTENT                 = 11,
    ND_RISK_HTTP_SUSPICIOUS_HEADER                  = 12,
    ND_RISK_HTTP_SUSPICIOUS_URL                     = 13,
    ND_RISK_HTTP_SUSPICIOUS_USER_AGENT              = 14,
    ND_RISK_INVALID_CHARACTERS                      = 15,
    ND_RISK_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT     = 16,
    ND_RISK_MALFORMED_PACKET                        = 17,
    ND_RISK_MALICIOUS_JA3                           = 18,
    ND_RISK_MALICIOUS_SHA1_CERTIFICATE              = 19,
    ND_RISK_POSSIBLE_EXPLOIT                        = 20,
    ND_RISK_PUNYCODE_IDN                            = 21,
    ND_RISK_RISKY_ASN                               = 22,
    ND_RISK_RISKY_DOMAIN                            = 23,
    ND_RISK_SMB_INSECURE_VERSION                    = 24,
    ND_RISK_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER   = 25,
    ND_RISK_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER   = 26,
    ND_RISK_SUSPICIOUS_DGA_DOMAIN                   = 27,
    ND_RISK_SUSPICIOUS_ENTROPY                      = 28,
    ND_RISK_TLS_CERTIFICATE_ABOUT_TO_EXPIRE         = 29,
    ND_RISK_TLS_CERTIFICATE_EXPIRED                 = 30,
    ND_RISK_TLS_CERTIFICATE_MISMATCH                = 31,
    ND_RISK_TLS_CERT_VALIDITY_TOO_LONG              = 32,
    ND_RISK_TLS_FATAL_ALERT                         = 33,
    ND_RISK_DEPR_TLS_MISSING_ALPN                   = 34,
    ND_RISK_TLS_MISSING_SNI                         = 35,
    ND_RISK_TLS_OBSOLETE_VERSION                    = 36,
    ND_RISK_TLS_SELFSIGNED_CERTIFICATE              = 37,
    ND_RISK_TLS_SUSPICIOUS_ESNI_USAGE               = 38,
    ND_RISK_TLS_SUSPICIOUS_EXTENSION                = 39,
    ND_RISK_TLS_UNCOMMON_ALPN                       = 40,
    ND_RISK_TLS_WEAK_CIPHER                         = 41,
    ND_RISK_UNSAFE_PROTOCOL                         = 42,
    ND_RISK_URL_POSSIBLE_RCE_INJECTION              = 43,
    ND_RISK_URL_POSSIBLE_SQL_INJECTION              = 44,
    ND_RISK_URL_POSSIBLE_XSS                        = 45,
    ND_RISK_UNIDIRECTIONAL_TRAFFIC                  = 46,
    ND_RISK_TLS_NOT_CARRYING_HTTPS                  = 47,
    ND_RISK_HTTP_OBSOLETE_SERVER                    = 48,
    ND_RISK_PERIODIC_FLOW                           = 49,
    ND_RISK_MINOR_ISSUES                            = 50,
    ND_RISK_TCP_ISSUES                              = 51,

    ND_RISK_MAX,
    ND_RISK_TODO                                    = 0xffffffff
} nd_risk_id_t;

typedef unordered_map<unsigned, const char *> nd_risks_t;

const nd_risks_t nd_risks = {
    { ND_RISK_NONE, "None" },

    { ND_RISK_ANONYMOUS_SUBSCRIBER, "Anonymous Subscriber" },
    { ND_RISK_BINARY_APPLICATION_TRANSFER, "Binary Application Transfer" },
    { ND_RISK_CLEAR_TEXT_CREDENTIALS, "Clear-Text Credentials" },
    { ND_RISK_DESKTOP_OR_FILE_SHARING_SESSION, "Desktop/File Sharing" },
    { ND_RISK_DNS_FRAGMENTED, "Fragmented DNS Message" },
    { ND_RISK_DNS_LARGE_PACKET, "Large DNS Packet (512+ bytes)" },
    { ND_RISK_DNS_SUSPICIOUS_TRAFFIC, "Suspicious DNS Traffic" },
    { ND_RISK_ERROR_CODE_DETECTED, "Error Code" },
    { ND_RISK_HTTP_CRAWLER_BOT, "Crawler/Bot" },
    { ND_RISK_HTTP_NUMERIC_IP_HOST, "HTTP Numeric IP Address" },
    { ND_RISK_HTTP_OBSOLETE_SERVER, "HTTP Obsolete Server" },
    { ND_RISK_HTTP_SUSPICIOUS_CONTENT, "HTTP Suspicious Content" },
    { ND_RISK_HTTP_SUSPICIOUS_HEADER, "HTTP Suspicious Header" },
    { ND_RISK_HTTP_SUSPICIOUS_URL, "HTTP Suspicious URL" },
    { ND_RISK_HTTP_SUSPICIOUS_USER_AGENT, "HTTP Suspicious User-Agent" },
    { ND_RISK_INVALID_CHARACTERS, "Text With Non-Printable Characters" },
    { ND_RISK_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT, "Known Protocol on Non-standard Port" },
    { ND_RISK_MALFORMED_PACKET, "Malformed Packet" },
    { ND_RISK_MALICIOUS_JA3, "Malicious JA3 Fingerprint" },
    { ND_RISK_MALICIOUS_SHA1_CERTIFICATE, "Malicious SSL Cert/SHA1 Fingerprint" },
    { ND_RISK_MINOR_ISSUES, "Minor Issues" },
    { ND_RISK_PERIODIC_FLOW, "Periodic Flow" },
    { ND_RISK_POSSIBLE_EXPLOIT, "Possible Exploit" },
    { ND_RISK_PUNYCODE_IDN, "IDN Domain Name" },
    { ND_RISK_RISKY_ASN, "Risky ASN" },
    { ND_RISK_RISKY_DOMAIN, "Risky Domain Name" },
    { ND_RISK_SMB_INSECURE_VERSION, "SMB Insecure Version" },
    { ND_RISK_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER, "SSH Obsolete Client Version/Cipher" },
    { ND_RISK_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER, "SSH Obsolete Server Version/Cipher" },
    { ND_RISK_SUSPICIOUS_DGA_DOMAIN, "Suspicious DGA Domain name" },
    { ND_RISK_SUSPICIOUS_ENTROPY, "Suspicious Entropy" },
    { ND_RISK_TCP_ISSUES, "TCP Connection Issues" },
    { ND_RISK_TLS_CERTIFICATE_ABOUT_TO_EXPIRE, "TLS Certificate About To Expire" },
    { ND_RISK_TLS_CERTIFICATE_EXPIRED, "TLS Certificate Expired" },
    { ND_RISK_TLS_CERTIFICATE_MISMATCH, "TLS Certificate Mismatch" },
    { ND_RISK_TLS_CERT_VALIDITY_TOO_LONG, "TLS Certificate Validity Too Long" },
    { ND_RISK_TLS_FATAL_ALERT, "TLS Fatal Alert" },
    { ND_RISK_TLS_MISSING_SNI, "TLS SNI Extension Not Found" },
    { ND_RISK_TLS_NOT_CARRYING_HTTPS, "TLS not carrying TLS" },
    { ND_RISK_TLS_OBSOLETE_VERSION, "Obsolete TLS (v1.1 or older)" },
    { ND_RISK_TLS_SELFSIGNED_CERTIFICATE, "Self-signed Certificate" },
    { ND_RISK_TLS_SUSPICIOUS_ESNI_USAGE, "TLS Suspicious ESNI Usage" },
    { ND_RISK_TLS_SUSPICIOUS_EXTENSION, "TLS Suspicious Extension" },
    { ND_RISK_TLS_UNCOMMON_ALPN, "Uncommon TLS ALPN" },
    { ND_RISK_TLS_WEAK_CIPHER, "Weak TLS Cipher" },
    { ND_RISK_UNIDIRECTIONAL_TRAFFIC, "Unidirectional Traffic" },
    { ND_RISK_UNSAFE_PROTOCOL, "Unsafe Protocol" },
    { ND_RISK_URL_POSSIBLE_RCE_INJECTION, "RCE Injection" },
    { ND_RISK_URL_POSSIBLE_SQL_INJECTION, "SQL Injection" },
    { ND_RISK_URL_POSSIBLE_XSS, "XSS Attack" },

    { ND_RISK_TODO, "TODO Add Risk" },
};

inline const char *nd_risk_get_name(nd_risk_id_t id)
{
    nd_risks_t::const_iterator it;
    if ((it = nd_risks.find(id)) == nd_risks.end()) return "None";
    return it->second;
}

typedef unordered_map<uint16_t, nd_risk_id_t> nd_ndpi_risk_t;

const nd_ndpi_risk_t nd_ndpi_risks = {
    { NDPI_ANONYMOUS_SUBSCRIBER, ND_RISK_ANONYMOUS_SUBSCRIBER },
    { NDPI_BINARY_APPLICATION_TRANSFER, ND_RISK_BINARY_APPLICATION_TRANSFER },
    { NDPI_CLEAR_TEXT_CREDENTIALS, ND_RISK_CLEAR_TEXT_CREDENTIALS },
    { NDPI_DESKTOP_OR_FILE_SHARING_SESSION, ND_RISK_DESKTOP_OR_FILE_SHARING_SESSION },
    { NDPI_DNS_FRAGMENTED, ND_RISK_DNS_FRAGMENTED },
    { NDPI_DNS_LARGE_PACKET, ND_RISK_DNS_LARGE_PACKET },
    { NDPI_DNS_SUSPICIOUS_TRAFFIC, ND_RISK_DNS_SUSPICIOUS_TRAFFIC },
    { NDPI_ERROR_CODE_DETECTED, ND_RISK_ERROR_CODE_DETECTED },
    { NDPI_HTTP_CRAWLER_BOT, ND_RISK_HTTP_CRAWLER_BOT },
    { NDPI_HTTP_NUMERIC_IP_HOST, ND_RISK_HTTP_NUMERIC_IP_HOST },
    { NDPI_HTTP_OBSOLETE_SERVER, ND_RISK_HTTP_OBSOLETE_SERVER },
    { NDPI_HTTP_SUSPICIOUS_CONTENT, ND_RISK_HTTP_SUSPICIOUS_CONTENT },
    { NDPI_HTTP_SUSPICIOUS_HEADER, ND_RISK_HTTP_SUSPICIOUS_HEADER },
    { NDPI_HTTP_SUSPICIOUS_URL, ND_RISK_HTTP_SUSPICIOUS_URL },
    { NDPI_HTTP_SUSPICIOUS_USER_AGENT, ND_RISK_HTTP_SUSPICIOUS_USER_AGENT },
    { NDPI_INVALID_CHARACTERS, ND_RISK_INVALID_CHARACTERS },
    { NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT, ND_RISK_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT },
    { NDPI_MALFORMED_PACKET, ND_RISK_MALFORMED_PACKET },
    { NDPI_MALICIOUS_JA3, ND_RISK_MALICIOUS_JA3 },
    { NDPI_MALICIOUS_SHA1_CERTIFICATE, ND_RISK_MALICIOUS_SHA1_CERTIFICATE },
    { NDPI_MINOR_ISSUES, ND_RISK_MINOR_ISSUES },
    { NDPI_NO_RISK, ND_RISK_NONE },
    { NDPI_PERIODIC_FLOW, ND_RISK_PERIODIC_FLOW},
    { NDPI_POSSIBLE_EXPLOIT, ND_RISK_POSSIBLE_EXPLOIT },
    { NDPI_PUNYCODE_IDN, ND_RISK_PUNYCODE_IDN },
    { NDPI_RISKY_ASN, ND_RISK_RISKY_ASN },
    { NDPI_RISKY_DOMAIN, ND_RISK_RISKY_DOMAIN },
    { NDPI_SMB_INSECURE_VERSION, ND_RISK_SMB_INSECURE_VERSION },
    { NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER, ND_RISK_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER },
    { NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER, ND_RISK_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER },
    { NDPI_SUSPICIOUS_DGA_DOMAIN, ND_RISK_SUSPICIOUS_DGA_DOMAIN },
    { NDPI_SUSPICIOUS_ENTROPY, ND_RISK_SUSPICIOUS_ENTROPY },
    { NDPI_TCP_ISSUES, ND_RISK_TCP_ISSUES },
    { NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE, ND_RISK_TLS_CERTIFICATE_ABOUT_TO_EXPIRE },
    { NDPI_TLS_CERTIFICATE_EXPIRED, ND_RISK_TLS_CERTIFICATE_EXPIRED },
    { NDPI_TLS_CERTIFICATE_MISMATCH, ND_RISK_TLS_CERTIFICATE_MISMATCH },
    { NDPI_TLS_CERT_VALIDITY_TOO_LONG, ND_RISK_TLS_CERT_VALIDITY_TOO_LONG },
    { NDPI_TLS_FATAL_ALERT, ND_RISK_TLS_FATAL_ALERT },
    { NDPI_TLS_MISSING_SNI, ND_RISK_TLS_MISSING_SNI },
    { NDPI_TLS_NOT_CARRYING_HTTPS, ND_RISK_TLS_NOT_CARRYING_HTTPS },
    { NDPI_TLS_OBSOLETE_VERSION, ND_RISK_TLS_OBSOLETE_VERSION },
    { NDPI_TLS_SELFSIGNED_CERTIFICATE, ND_RISK_TLS_SELFSIGNED_CERTIFICATE },
    { NDPI_TLS_SUSPICIOUS_ESNI_USAGE, ND_RISK_TLS_SUSPICIOUS_ESNI_USAGE },
    { NDPI_TLS_SUSPICIOUS_EXTENSION, ND_RISK_TLS_SUSPICIOUS_EXTENSION },
    { NDPI_TLS_UNCOMMON_ALPN, ND_RISK_TLS_UNCOMMON_ALPN },
    { NDPI_TLS_WEAK_CIPHER, ND_RISK_TLS_WEAK_CIPHER },
    { NDPI_UNIDIRECTIONAL_TRAFFIC, ND_RISK_UNIDIRECTIONAL_TRAFFIC },
    { NDPI_UNSAFE_PROTOCOL, ND_RISK_UNSAFE_PROTOCOL },
    { NDPI_URL_POSSIBLE_RCE_INJECTION, ND_RISK_URL_POSSIBLE_RCE_INJECTION },
    { NDPI_URL_POSSIBLE_SQL_INJECTION, ND_RISK_URL_POSSIBLE_SQL_INJECTION },
    { NDPI_URL_POSSIBLE_XSS, ND_RISK_URL_POSSIBLE_XSS },
};

inline nd_risk_id_t nd_ndpi_risk_find(uint16_t id)
{
    nd_ndpi_risk_t::const_iterator it;
    if ((it = nd_ndpi_risks.find(id)) == nd_ndpi_risks.end())
        return ND_RISK_TODO;

    return it->second;
}

nd_risk_id_t nd_risk_lookup(const string &name);

#endif // _ND_RISKS_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
