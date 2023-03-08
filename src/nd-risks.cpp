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

#include <pcap/pcap.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#include <curl/curl.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-ndpi.h"
#include "nd-risks.h"
#include "nd-serializer.h"
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
#include "nd-category.h"
#include "nd-flow.h"

nd_risk_id_t nd_risk_lookup(const string &name)
{
    for (auto &i : nd_risks) {
        if (strcasecmp(name.c_str(), i.second)) continue;
        return (nd_risk_id_t)i.first;
    }

    return ND_RISK_MAX;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
