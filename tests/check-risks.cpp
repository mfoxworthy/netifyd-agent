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

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

using namespace std;

class ndPluginLoader;

#include <netifyd.h>
#include <nd-ndpi.h>
#include <nd-risks.h>
#include <nd-serializer.h>
#include <nd-packet.h>
#include <nd-json.h>
#include <nd-util.h>
#include <nd-thread.h>
#include <nd-addr.h>
#ifdef _ND_USE_NETLINK
#include <nd-netlink.h>
#endif
#include <nd-apps.h>
#include <nd-protos.h>
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
