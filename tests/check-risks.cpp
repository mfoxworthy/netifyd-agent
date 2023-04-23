// Netify Agent Test Suite
// Copyright (C) 2022 eGloo Incorporated <http://www.egloo.ca>

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
#include <linux/if_packet.h>

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
#include "nd-flow-parser.h"
#include "nd-dhc.h"
#include "nd-fhc.h"
#include "nd-thread.h"
#ifdef _ND_USE_PLUGINS
class ndInstanceStatus;
#include "nd-plugin.h"
#endif
#include "nd-instance.h"
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

int main(int argc, char *argv[])
{
    int rc = 0;

    cout << "Testing Netify Agent Risks..." << endl;

    ndpi_global_init();

    cout << endl << "nDPI risks count: " <<
        NDPI_MAX_RISK << endl;
    cout << "Netify Agent risks count: " <<
        ND_RISK_MAX << endl << endl;

    for (uint16_t id = 0;
        id < NDPI_MAX_RISK; id++) {

        auto it = nd_ndpi_risks.find(id);
        if (it != nd_ndpi_risks.end()) continue;

        ndpi_risk_enum rid = (ndpi_risk_enum)id;

        ndpi_risk_info const * const risk_info = ndpi_risk2severity(rid);
        if(risk_info == NULL) {
            rc = 1;
            cout << "ID# " << id << " (ndpi_risk2severity: UNKNOWN/ERROR)" << endl;
            continue;
        }

        rc = 1;
        cout << "ID# " << id << " (" << ndpi_risk2str(risk_info->risk) << ")" << endl;
    }

    if (rc != 0) cout << endl;
    cout << "Test result: " << ((rc == 0) ? "PASS" : "FAIL") << endl << endl;

    return rc;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
