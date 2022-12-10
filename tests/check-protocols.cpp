// Netify Agent Test Suite
// Copyright (C) 2022 eGloo Incorporated <http://www.egloo.ca>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <stdexcept>
#include <vector>
#include <set>
#include <map>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <fstream>
#include <sstream>
#include <atomic>
#include <regex>
#include <mutex>
#include <algorithm>
#include <bitset>

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#include <pcap/pcap.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/xt_connlabel.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

using namespace std;

class ndPluginLoader;

#include <netifyd.h>
#include <nd-ndpi.h>
#include <nd-packet.h>
#include <nd-json.h>
#include <nd-util.h>
#include <nd-thread.h>
#ifdef _ND_USE_NETLINK
#include <nd-netlink.h>
#endif
#include <nd-addr.h>
#include <nd-apps.h>
#include <nd-protos.h>
#include <nd-risks.h>
#include <nd-category.h>
#include <nd-flow.h>
class ndFlowMap;
#ifdef _ND_USE_PLUGINS
#include <nd-plugin.h>
#endif
#include <nd-flow-map.h>

extern ndApplications *nd_apps;

int main(int argc, char *argv[])
{
    int rc = 0;
    char proto_name[64];

    cout << "Testing Netify Agent Protocols..." << endl;

    ndpi_global_init();
    ndpi_detection_module_struct *ndpi = nd_ndpi_init();

    cout << endl << "nDPI protocol count: " <<
        NDPI_LAST_IMPLEMENTED_PROTOCOL << endl;
    cout << "Netify Agent protocol count: " <<
        nd_ndpi_protos.size() << endl << endl;

    for (uint16_t id = 0;
        id < NDPI_LAST_IMPLEMENTED_PROTOCOL; id++) {

        auto it = nd_ndpi_protos.find(id);
        if (find(
            nd_ndpi_disabled.begin(),
            nd_ndpi_disabled.end(), id) != nd_ndpi_disabled.end()
        ) continue;

        if (it != nd_ndpi_protos.end()) continue;

        ndpi_protocol proto = { id, 0 };
        ndpi_protocol2name(
            ndpi, proto, proto_name, sizeof(proto_name)
        );

        rc = 1;
        cout << "ID# " << id << " (" << proto_name << ")" << endl;
    }

    if (rc != 0) cout << endl;
    cout << "Test result: " << ((rc == 0) ? "PASS" : "FAIL") << endl << endl;

    return rc;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
