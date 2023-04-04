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
#include <cstring>
#include <map>
#include <set>
#include <list>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <regex>
#include <mutex>
#include <bitset>
#include <atomic>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <errno.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#include <pcap/pcap.h>

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
#include "nd-ndpi.h"
#include "nd-util.h"
#include "nd-addr.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-json.h"
#include "nd-util.h"

// Enable flow hash cache debug logging
//#define _ND_DEBUG_FHC 1

#include "nd-fhc.h"

ndFlowHashCache::ndFlowHashCache(size_t cache_size)
    : cache_size(cache_size)
{
    int rc;

    if ((rc = pthread_mutex_init(&lock, NULL)) != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_init", rc);
}

ndFlowHashCache::~ndFlowHashCache()
{
    pthread_mutex_destroy(&lock);
}

void ndFlowHashCache::Push(const string &lower_hash, const string &upper_hash)
{
    int rc;

    if ((rc = pthread_mutex_lock(&lock)) != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_lock", rc);

    nd_fhc_map::const_iterator i = lookup.find(lower_hash);

    if (i != lookup.end()) {
        nd_dprintf("WARNING: Found existing hash in flow hash cache on push.\n");
    }
    else {
        if (lookup.size() == cache_size) {
#if _ND_DEBUG_FHC
            nd_dprintf("Purging flow hash cache entries, size: %lu\n",
                lookup.size());
#endif
            for (size_t n = 0; n < cache_size / ND_GCI.fhc_purge_divisor; n++) {
                pair<string, string> j = index.back();

                nd_fhc_map::iterator k = lookup.find(j.first);
                if (k == lookup.end()) {
                    nd_dprintf("WARNING: flow hash cache index not found in map\n");
                }
                else
                    lookup.erase(k);

                index.pop_back();
            }
        }

        index.push_front(make_pair(lower_hash, upper_hash));
        lookup[lower_hash] = index.begin();
#if _ND_DEBUG_FHC
        nd_dprintf("Flow hash cache entries: %lu\n", lookup.size());
#endif
    }

    if ((rc = pthread_mutex_unlock(&lock)) != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_unlock", rc);
}

bool ndFlowHashCache::Pop(const string &lower_hash, string &upper_hash)
{
    int rc;
    bool found = false;

    if ((rc = pthread_mutex_lock(&lock)) != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_lock", rc);

    nd_fhc_map::iterator i = lookup.find(lower_hash);

    if ((found = i != lookup.end())) {

        upper_hash = i->second->second;

        index.erase(i->second);

        index.push_front(make_pair(lower_hash, upper_hash));

        i->second = index.begin();
    }

    if ((rc = pthread_mutex_unlock(&lock)) != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_unlock", rc);

    return found;
}

void ndFlowHashCache::Load(void)
{
    string filename;

    switch (ND_GCI.fhc_save) {
    case ndFHC_PERSISTENT:
        filename = ND_GCI.path_state_persistent + ND_FLOW_HC_FILE_NAME;
        break;
    case ndFHC_VOLATILE:
        filename = ND_GCI.path_state_volatile + ND_FLOW_HC_FILE_NAME;
        break;
    default:
        return;
    }

    FILE *hf = fopen(filename.c_str(), "rb");
    if (hf != NULL) {
        do {
            string digest_lower, digest_mdata;
            uint8_t digest[SHA1_DIGEST_LENGTH * 2];

            if (fread(digest, SHA1_DIGEST_LENGTH * 2, 1, hf) != 1) break;

            digest_lower.assign((const char *)digest, SHA1_DIGEST_LENGTH);
            digest_mdata.assign((const char *)&digest[SHA1_DIGEST_LENGTH],
                SHA1_DIGEST_LENGTH);

            Push(digest_lower, digest_mdata);
        }
        while (! feof(hf));

        fclose(hf);
    }

    if (index.size())
        nd_dprintf("Loaded %lu flow hash cache entries.\n", index.size());
}

void ndFlowHashCache::Save(void)
{
    string filename;

    switch (ND_GCI.fhc_save) {
    case ndFHC_PERSISTENT:
        filename = ND_GCI.path_state_persistent + ND_FLOW_HC_FILE_NAME;
        break;
    case ndFHC_VOLATILE:
        filename = ND_GCI.path_state_volatile + ND_FLOW_HC_FILE_NAME;
        break;
    default:
        return;
    }

    FILE *hf = fopen(filename.c_str(), "wb");
    if (hf == NULL) {
        nd_printf("WARNING: Error saving flow hash cache: %s: %s\n",
            filename.c_str(), strerror(errno));
        return;
    }

    nd_fhc_list::iterator i;
    for (i = index.begin(); i != index.end(); i++) {
        fwrite((*i).first.c_str(), 1, SHA1_DIGEST_LENGTH, hf);
        fwrite((*i).second.c_str(), 1, SHA1_DIGEST_LENGTH, hf);
    }
    fclose(hf);

    nd_dprintf("Saved %lu flow hash cache entries.\n", index.size ());
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
