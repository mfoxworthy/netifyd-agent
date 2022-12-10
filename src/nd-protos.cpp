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
#include <vector>
#include <queue>
#include <set>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <fstream>
#include <sstream>
#include <atomic>
#include <regex>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <bitset>
#include <cstdlib>
#include <csignal>
#include <mutex>
#include <bitset>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>

#define __FAVOR_BSD 1
#include <netinet/ip.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#include <pcap/pcap.h>

#include <curl/curl.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#include "nd-packet.h"
#include "nd-json.h"
#include "nd-thread.h"
#include "nd-util.h"
#include "nd-addr.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-apps.h"
#include "nd-protos.h"
#include "nd-risks.h"
#include "nd-category.h"
#include "nd-flow.h"

const nd_proto_id_t nd_ndpi_proto_find(uint16_t id, const ndFlow *flow)
{
    if (id == NDPI_PROTOCOL_UNKNOWN) return ND_PROTO_UNKNOWN;

    auto it_pm = nd_ndpi_portmap.find(id);
    if (it_pm != nd_ndpi_portmap.end()) {
        for (auto &it_entry : it_pm->second) {
            if (flow->lower_addr.GetPort() != it_entry.first &&
                flow->upper_addr.GetPort() != it_entry.first)
                continue;
            return it_entry.second;
        }
    }

    nd_ndpi_proto_t::const_iterator it;
    if ((it = nd_ndpi_protos.find(id)) == nd_ndpi_protos.end())
        return ND_PROTO_TODO;

    return it->second;
}

const uint16_t nd_ndpi_proto_find(unsigned id)
{
    if (id == ND_PROTO_UNKNOWN) return NDPI_PROTOCOL_UNKNOWN;

    for (auto &it : nd_ndpi_protos) {
        if (it.second != id) continue;
        return it.first;
    }

    return NDPI_PROTOCOL_UNKNOWN;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
