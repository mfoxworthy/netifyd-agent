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

#include <string>
#include <stdexcept>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <regex>
#include <mutex>
#include <bitset>
#include <atomic>

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <net/if.h>
#include <net/if_arp.h>
#if defined(__linux__)
#include <linux/if_packet.h>
#elif defined(__FreeBSD__)
#include <net/if_dl.h>
#endif

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-ndpi.h"
#include "nd-base64.h"
#include "nd-risks.h"
#include "nd-serializer.h"
#include "nd-packet.h"
#include "nd-json.h"
#include "nd-util.h"
#include "nd-addr.h"
#include "nd-apps.h"
#include "nd-protos.h"

void nd_json_to_string(const json &j, string &output, bool pretty)
{
    output = j.dump(
        pretty ? ND_JSON_INDENT : -1,
        ' ', true, json::error_handler_t::replace
    );

    vector<pair<regex *, string> >::const_iterator i;
    for (i = ndGC.privacy_regex.begin();
        i != ndGC.privacy_regex.end(); i++) {

        string result = regex_replace(output, *((*i).first), (*i).second);
        if (result.size()) output = result;
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
