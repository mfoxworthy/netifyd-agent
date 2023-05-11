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

#include <iomanip>
#include <iostream>
#include <set>
#include <map>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <vector>
#include <locale>
#include <atomic>
#include <regex>
#include <mutex>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <locale.h>
#include <syslog.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <netdb.h>
#include <netinet/in.h>

#include <net/if.h>
#include <net/if_arp.h>
#if defined(__linux__)
#include <linux/if_packet.h>
#elif defined(__FreeBSD__)
#include <net/if_dl.h>
#endif

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <curl/curl.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <resolv.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

#if defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
#include <gperftools/malloc_extension.h>
#elif defined(HAVE_MALLOC_TRIM)
#include <malloc.h>
#endif

#include <radix/radix_tree.hpp>

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-signal.h"
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
#include "nd-protos.h"
#include "nd-category.h"
#include "nd-flow.h"
#include "nd-flow-map.h"
#include "nd-dhc.h"
#include "nd-fhc.h"
#include "nd-thread.h"
#ifdef _ND_USE_PLUGINS
class ndInstanceStatus;
#include "nd-plugin.h"
#endif
#include "nd-instance.h"
#include "nd-flow-parser.h"
#ifdef _ND_USE_CONNTRACK
#include "nd-conntrack.h"
#endif
#include "nd-detection.h"
#include "nd-capture.h"
#ifdef _ND_USE_LIBPCAP
#include "nd-capture-pcap.h"
#endif
#ifdef _ND_USE_TPACKETV3
#include "nd-capture-tpv3.h"
#endif
#ifdef _ND_USE_NFQUEUE
#include "nd-capture-nfq.h"
#endif
#include "nd-base64.h"
#include "nd-napi.h"

ndDNSHintCache::ndDNSHintCache()
{
#ifdef HAVE_CXX11
    map_ar.reserve(ND_HASH_BUCKETS_DNSARS);
#endif
}

void ndDNSHintCache::Insert(const ndAddr &addr, const string &hostname)
{
    if (! addr.IsValid() || ! addr.IsIP() || addr.IsNetwork()) {
        nd_dprintf("Invalid DHC address: %s\n", addr.GetString().c_str());
        return;
    }

    ndAddr::Type type;
    ndInstance::GetInstance().addr_types.Classify(type, addr);

    if (type != ndAddr::atOTHER) {
        nd_dprintf("Invalid DHC address type: %d: %s\n",
            type, addr.GetString().c_str());
        return;
    }

    const uint8_t *sa = addr.GetAddress();
    if (sa == nullptr) {
        nd_dprintf("Invalid DHC address data.\n");
        return;
    }

    sha1 ctx;
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);
    sha1_write(&ctx, sa, addr.GetAddressSize());

    digest.assign((const char *)sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);

    unique_lock<mutex> ul(lock);

    nd_dns_tuple ar(time_t(time(NULL) + ndGC.ttl_dns_entry), hostname);
    nd_dhc_insert i = map_ar.insert(nd_dhc_insert_pair(digest, ar));

    if (! i.second)
        i.first->second.first = time(NULL) + ndGC.ttl_dns_entry;
}

void ndDNSHintCache::Insert(const string &digest, const string &hostname)
{
    int i = 0;
    uint8_t v;
    const char *p = digest.c_str();
    string _digest;

    // TODO: Verify length of digest (must be SHA1_DIGEST_LENGTH).

    do {
        if (sscanf(p, "%2hhx", &v) != 1) break;
        _digest.append(1, v);
        p += 2;
    }
    while (++i < SHA1_DIGEST_LENGTH);

    if (_digest.size() != SHA1_DIGEST_LENGTH) return;

    nd_dns_tuple ar(time_t(time(NULL) + ndGC.ttl_dns_entry), hostname);
    map_ar.insert(nd_dhc_insert_pair(_digest, ar));
}

bool ndDNSHintCache::Lookup(const ndAddr &addr, string &hostname)
{
    if (! addr.IsValid() || ! addr.IsIP() || addr.IsNetwork()) {
        nd_dprintf("Invalid DHC address: %s\n", addr.GetString().c_str());
        return false;
    }

    const uint8_t *sa = addr.GetAddress();
    size_t sa_length = addr.GetAddressSize();

    if (sa == nullptr || sa_length == 0) {
        nd_dprintf("Invalid DHC address data.\n");
        return false;
    }

    sha1 ctx;
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);
    sha1_write(&ctx, sa, sa_length);

    digest.assign((const char *)sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);

    return Lookup(digest, hostname);
}

bool ndDNSHintCache::Lookup(const string &digest, string &hostname)
{
    bool found = false;
    unique_lock<mutex> ul(lock);

    nd_dns_ar::iterator i = map_ar.find(digest);
    if (i != map_ar.end()) {
        found = true;
        hostname = i->second.second;
        i->second.first = time(NULL) + ndGC.ttl_dns_entry;
    }

    return found;
}

size_t ndDNSHintCache::Purge(void)
{
    unique_lock<mutex> ul(lock);
    size_t purged = 0, remaining = 0;

    nd_dns_ar::iterator i = map_ar.begin();
    while (i != map_ar.end()) {
        if (i->second.first < time(NULL)) {
            i = map_ar.erase(i);
            purged++;
        }
        else
            i++;
    }

    remaining = map_ar.size();

    if (purged > 0 && remaining > 0)
        nd_dprintf("Purged %u DNS cache entries, %u active.\n", purged, remaining);

    return purged;
}

void ndDNSHintCache::Load(void)
{
    int rc;
    long ttl;
    char header[1024], *host, *digest;
    size_t loaded = 0, line = 1;
    string filename;
    FILE *hf = NULL;

    switch (ndGC.dhc_save) {
    case ndDHC_PERSISTENT:
        filename = ndGC.path_state_persistent + ND_DHC_FILE_NAME;
        break;
    case ndDHC_VOLATILE:
        filename = ndGC.path_state_volatile + ND_DHC_FILE_NAME;
        break;
    default:
        return;
    }

    if (! (hf = fopen(filename.c_str(), "r"))) return;

    if (fgets(header, sizeof(header), hf) == NULL) { fclose(hf); return; }

    unique_lock<mutex> ul(lock);

    while (! feof(hf)) {
        line++;
        if ((rc = fscanf(hf,
            " \"%m[0-9A-z.-]\" , %m[0-9A-Fa-f] , %ld\n",
            &host, &digest, &ttl)) != 3) {
            nd_printf("%s: parse error at line #%u [%d]\n",
                filename.c_str(), line, rc);
            if (rc >= 1) free(host);
            if (rc >= 2) free(digest);
            break;
        }

        Insert(digest, host);

        free(host);
        free(digest);

        loaded++;
    }

    nd_dprintf("Loaded %u of %u DNS cache entries.\n",
        map_ar.size(), loaded);

    fclose(hf);
}

void ndDNSHintCache::Save(void)
{
    string digest;
    size_t saved = 0;
    string filename;
    FILE *hf = NULL;

    switch (ndGC.dhc_save) {
    case ndDHC_PERSISTENT:
        filename = ndGC.path_state_persistent + ND_DHC_FILE_NAME;
        break;
    case ndDHC_VOLATILE:
        filename = ndGC.path_state_volatile + ND_DHC_FILE_NAME;
        break;
    default:
        return;
    }

    if (! (hf = fopen(filename.c_str(), "w"))) return;

    unique_lock<mutex> ul(lock);

    fprintf(hf, "\"host\",\"addr_digest\",\"ttl\"\n");

    for (nd_dns_ar::iterator i = map_ar.begin();
        i != map_ar.end(); i++) {

        nd_sha1_to_string((const uint8_t *)i->first.c_str(), digest);

        if (fprintf(hf, "\"%s\",%s,%u\n", i->second.second.c_str(),
            digest.c_str(), (unsigned)(i->second.first - time(NULL))) > 0)
            saved++;
    }

    nd_dprintf("Saved %u of %u DNS cache entries.\n",
        saved, map_ar.size());

    fclose(hf);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
