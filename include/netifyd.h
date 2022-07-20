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

#ifndef _ND_H
#define _ND_H

#include "nd-json-response-code.h"

#ifndef AF_LINK
#define AF_LINK AF_PACKET
#endif

#ifndef ETH_ALEN
#include <net/ethernet.h>
#if !defined(ETH_ALEN) && defined(ETHER_ADDR_LEN)
#define ETH_ALEN ETHER_ADDR_LEN
#endif
#endif
#ifndef ETH_ALEN
#error Unable to define ETH_ALEN.
#endif

#if defined(_ND_USE_NETLINK) && defined(HAVE_LINUX_NETLINK_H)
#include <linux/netlink.h>
#endif

#include <sys/param.h>
#include <sys/socket.h>

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#if __cplusplus >= 201103L &&                             \
    (!defined(__GLIBCXX__) || (__cplusplus >= 201402L) || \
        (defined(_GLIBCXX_REGEX_DFS_QUANTIFIERS_LIMIT) || \
         defined(_GLIBCXX_REGEX_STATE_LIMIT)           || \
             (defined(_GLIBCXX_RELEASE)                && \
             _GLIBCXX_RELEASE > 4)))
#define HAVE_WORKING_REGEX 1
#else
#undef HAVE_WORKING_REGEX
#endif

#define ND_MAX_HOSTNAME         256

#define ND_STATS_INTERVAL       15      // Collect stats every N seconds
#define ND_MAX_BACKLOG_KB       2048    // Maximum upload queue size in kB
#define ND_DETECTION_TICKS      1000    // Ticks-per-second (1000 = milliseconds)
#define ND_TTL_IDLE_FLOW        30      // Purge idle flows older than this (30s)
#define ND_TTL_IDLE_TCP_FLOW    300     // Purge idle TCP flows older than this (5m)
#define ND_TTL_IDLE_DHC_ENTRY  (60 * 30)// Purge TTL for idle DNS cache entries.
#define ND_TTL_PCAP_SELECT_USEC 500     // Minimum pcap select timeout in micros.
#define ND_HASH_BUCKETS_FLOWS   1613    // Initial flows map bucket count.
#define ND_HASH_BUCKETS_DNSARS  1613    // DNS cache address record hash buckets.

#define ND_MAX_FHC_ENTRIES      10000   // Maximum number of flow hash cache entries.
#define ND_FHC_PURGE_DIVISOR    10      // Divisor of FHC_ENTRIES to delete on purge.

#define ND_MAX_PKT_QUEUE_KB     8192    // Maximum packet queue size in kB
#define ND_PKTQ_FLUSH_DIVISOR   10      // Divisor of PKT_QUEUE_KB packets to flush.

#define ND_MAX_DETECTION_PKTS   32      // Maximum number of packets to process.

#ifndef ND_VOLATILE_STATEDIR
#define ND_VOLATILE_STATEDIR    "/var/run/netifyd"
#endif

#ifndef ND_PERSISTENT_STATEDIR
#define ND_PERSISTENT_STATEDIR  "/etc/netify.d"
#endif

#ifndef ND_DATADIR
#define ND_DATADIR              "/usr/share/netifyd"
#endif

#ifndef ND_CONF_FILE_NAME
#define ND_CONF_FILE_NAME       "/etc/netifyd.conf"
#endif

#ifndef ND_PID_FILE_NAME
#define ND_PID_FILE_NAME        ND_VOLATILE_STATEDIR "/netifyd.pid"
#endif

#define ND_JSON_VERSION         1.9     // JSON format version
#define ND_JSON_FILE_USER       "root"
#ifndef BSD4_4
#define ND_JSON_FILE_GROUP      "root"
#else
#define ND_JSON_FILE_GROUP      "wheel"
#endif
#define ND_JSON_FILE_MODE       0600
#define ND_JSON_FILE_EXPORT     ND_VOLATILE_STATEDIR "/sink-request.json"
#define ND_JSON_FILE_RESPONSE   ND_VOLATILE_STATEDIR "/sink-response.json"
#define ND_JSON_FILE_BAD_SEND   ND_VOLATILE_STATEDIR "/sink-bad-request.json"
#define ND_JSON_FILE_BAD_RECV   ND_VOLATILE_STATEDIR "/sink-bad-response.json"
#define ND_JSON_FILE_STATUS     ND_VOLATILE_STATEDIR "/status.json"
#define ND_JSON_DATA_CHUNKSIZ   4096
#define ND_JSON_INDENT          4

#define ND_PCAP_SNAPLEN         65535   // Capture snap length
#define ND_PCAP_READ_TIMEOUT    500     // Milliseconds

#ifndef ND_URL_SINK
#define ND_URL_SINK             "https://sink.netify.ai/provision/"
#endif
#define ND_URL_SINK_PATH        ND_PERSISTENT_STATEDIR "/sink.url"
#define ND_URL_SINK_LEN         256

#define ND_SINK_MAX_POST_ERRORS 3       // Maximum number of sink POST errors.

#define ND_COOKIE_JAR           ND_VOLATILE_STATEDIR "/cookie.jar"

#define ND_SINK_CONNECT_TIMEOUT 30      // Default 30-second connection timeout
#define ND_SINK_XFER_TIMEOUT    300     // Default 5-minute upload timeout

#define ND_AGENT_UUID_PATH      ND_PERSISTENT_STATEDIR "/agent.uuid"
#define ND_AGENT_UUID_NULL      "00-00-00-00"
#define ND_AGENT_UUID_LEN       11

#define ND_AGENT_SERIAL_PATH    ND_PERSISTENT_STATEDIR "/serial.uuid"
#define ND_AGENT_SERIAL_NULL    "-"
#define ND_AGENT_SERIAL_LEN     32

#define ND_SITE_UUID_PATH       ND_PERSISTENT_STATEDIR "/site.uuid"
#define ND_SITE_UUID_NULL       "-"
#define ND_SITE_UUID_LEN        36

#define ND_ETHERS_FILE_NAME     "/etc/ethers"

#ifdef _ND_USE_WATCHDOGS
#define ND_WD_UPLOAD            ND_VOLATILE_STATEDIR "/upload.wd"
#endif

// Compress data if it's over this size (bytes)
#define ND_COMPRESS_SIZE       (1024 * 10)
#define ND_ZLIB_CHUNK_SIZE      16384   // Compress this many bytes at a time

#define ND_SOCKET_PORT          "7150"
#define ND_SOCKET_PATH_MODE     0640
#define ND_SOCKET_PATH_USER     "root"
#define ND_SOCKET_PATH_GROUP    "root"

#ifndef PACKAGE_URL
#define PACKAGE_URL             "https://www.netify.ai/"
#endif

#define ND_CONF_APP_BASE        "netify-apps.conf"
#define ND_CONF_APP_PATH        ND_PERSISTENT_STATEDIR "/" ND_CONF_APP_BASE

#define ND_CONF_CAT_BASE        "netify-categories.json"
#define ND_CONF_CAT_PATH        ND_PERSISTENT_STATEDIR "/" ND_CONF_CAT_BASE

#define ND_CONF_LEGACY_BASE     "netify-sink.conf"
#define ND_CONF_LEGACY_PATH     ND_PERSISTENT_STATEDIR "/" ND_CONF_LEGACY_BASE

#define ND_STR_ETHALEN          (ETH_ALEN * 2 + ETH_ALEN - 1)

#define ND_PRIVATE_IPV4         "127.255.0."
#define ND_PRIVATE_IPV6         "fe:80::ffff:7fff:"

#define ND_API_UPDATE_TTL       (3600 * 24)
#define ND_API_UPDATE_URL       "https://api.netify.ai/api/v1"
#define ND_API_VENDOR           "EG"

#include "nd-sha1.h"

typedef unordered_map<string, vector<string> > nd_device_addrs;
typedef map<string, pair<mutex *, nd_device_addrs *> > nd_device;
typedef unordered_map<string, string> nd_device_ether;
typedef vector<pair<bool, string> > nd_interface;
typedef vector<pair<string, string> > nd_device_addr;
typedef map<string, string> nd_device_filter;
typedef map<string, string> nd_netlink_device;
typedef map<string, string> nd_inotify_watch;
#ifdef _ND_USE_PLUGINS
class ndPluginLoader;
typedef map<string, ndPluginLoader *> nd_plugins;
#endif
typedef pair<struct sockaddr_storage, struct sockaddr_storage> nd_private_addr;

typedef struct nd_agent_stats_t
{
    long cpus;
    struct timespec ts_epoch;
    struct timespec ts_now;
    uint32_t flows;
    uint32_t flows_prev;
    double cpu_user;
    double cpu_user_prev;
    double cpu_system;
    double cpu_system_prev;
#if (SIZEOF_LONG == 4)
    uint32_t maxrss_kb;
    uint32_t maxrss_kb_prev;
#elif (SIZEOF_LONG == 8)
    uint64_t maxrss_kb;
    uint64_t maxrss_kb_prev;
#endif
#if (defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)) || \
    (defined(_ND_USE_LIBJEMALLOC) && defined(HAVE_JEMALLOC_JEMALLOC_H))
    size_t tcm_alloc_kb;
    size_t tcm_alloc_kb_prev;
#endif
    bool dhc_status;
    size_t dhc_size;
    bool sink_uploads;
    bool sink_status;
    size_t sink_queue_size;
    ndJsonResponseCode sink_resp_code;
} nd_agent_stats;

typedef struct nd_packet_stats_t
{
    struct pkt_t {
        uint64_t raw;
        uint64_t eth;
        uint64_t mpls;
        uint64_t pppoe;
        uint64_t vlan;
        uint64_t frags;
        uint64_t discard;
        uint32_t maxlen;
        uint64_t ip;
        uint64_t ip4;
        uint64_t ip6;
        uint64_t icmp;
        uint64_t igmp;
        uint64_t tcp;
        uint64_t tcp_seq_error;
        uint64_t tcp_resets;
        uint64_t udp;
        uint64_t ip_bytes;
        uint64_t ip4_bytes;
        uint64_t ip6_bytes;
        uint64_t wire_bytes;
        uint64_t discard_bytes;
        uint64_t queue_dropped;
    } pkt;

    struct flow_t {
        uint64_t dropped;
    } flow;

    struct pcap_stat pcap_last;

    inline nd_packet_stats_t& operator+=(const nd_packet_stats_t &rhs) {
        pkt.raw += rhs.pkt.raw;
        pkt.eth += rhs.pkt.eth;
        pkt.mpls += rhs.pkt.mpls;
        pkt.pppoe += rhs.pkt.pppoe;
        pkt.vlan += rhs.pkt.vlan;
        pkt.frags += rhs.pkt.frags;
        pkt.discard += rhs.pkt.discard;
        if (rhs.pkt.maxlen > pkt.maxlen)
            pkt.maxlen = rhs.pkt.maxlen;
        pkt.ip += rhs.pkt.ip;
        pkt.ip4 += rhs.pkt.ip4;
        pkt.ip6 += rhs.pkt.ip6;
        pkt.icmp += rhs.pkt.icmp;
        pkt.igmp += rhs.pkt.igmp;
        pkt.tcp += rhs.pkt.tcp;
        pkt.tcp_seq_error += rhs.pkt.tcp_seq_error;
        pkt.tcp_resets += rhs.pkt.tcp_resets;
        pkt.udp += rhs.pkt.udp;
        pkt.ip_bytes += rhs.pkt.ip_bytes;
        pkt.ip4_bytes += rhs.pkt.ip4_bytes;
        pkt.ip6_bytes += rhs.pkt.ip6_bytes;
        pkt.wire_bytes += rhs.pkt.wire_bytes;
        pkt.discard_bytes += rhs.pkt.discard_bytes;
        pkt.queue_dropped += rhs.pkt.queue_dropped;
        pcap_last.ps_recv += rhs.pcap_last.ps_recv;
        pcap_last.ps_drop += rhs.pcap_last.ps_drop;
        pcap_last.ps_ifdrop += rhs.pcap_last.ps_ifdrop;
        return *this;
    }

    inline void reset(void) {
        memset(&pkt, 0, sizeof(struct pkt_t));
    }
} nd_packet_stats;

typedef map<string, nd_packet_stats *> nd_stats;

void nd_json_agent_hello(string &json_string);
void nd_json_agent_status(json &j);
void nd_json_protocols(string &json_string);

struct ndInterfaceAddress
{
    sa_family_t family;
    union {
        uint8_t mac[ETH_ALEN];
        struct sockaddr_storage ip;
    };
};

typedef vector<struct ndInterfaceAddress *> nd_interface_addr_array;
typedef map<string, nd_interface_addr_array *> nd_interface_addr_map;
typedef pair<string, nd_interface_addr_array *> nd_interface_addr_pair;
typedef pair<nd_interface_addr_map::iterator, bool> nd_interface_addr_insert;

class ndException : public runtime_error
{
public:
    explicit ndException(
        const string &where_arg, const string &what_arg) throw();
    virtual ~ndException() throw();

    virtual const char *what() const throw();

    string where_arg;
    string what_arg;
    const char *message;
};

class ndSystemException : public runtime_error
{
public:
    explicit ndSystemException(
        const string &where_arg, const string &what_arg, int why_arg) throw();
    virtual ~ndSystemException() throw();

    virtual const char *what() const throw();

    string where_arg;
    string what_arg;
    int why_arg;
    const char *message;
};

#endif // _ND_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
