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
#include <list>
#include <vector>
#include <set>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <regex>
#include <mutex>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <errno.h>

#include <arpa/inet.h>

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-packet.h"
#include "nd-json.h"
#include "nd-util.h"
#include "nd-apps.h"
#include "nd-protos.h"
#include "nd-risks.h"
#include "nd-category.h"
#include "nd-flow.h"
#include "nd-flow-map.h"

ndFlowMap *nd_flow_buckets = NULL;

ndFlowMap::ndFlowMap(size_t buckets)
    : buckets(buckets)
{
    int rc;

    for (size_t i = 0; i < buckets; i++) {
        nd_flow_map *b = new nd_flow_map;
        if (b == NULL)
            throw ndSystemException(__PRETTY_FUNCTION__, "new nd_flow_map", ENOMEM);
#ifdef HAVE_CXX11
        b->reserve(ND_HASH_BUCKETS_FLOWS);
#endif
        bucket.push_back(b);
        pthread_mutex_t *m = new pthread_mutex_t;
        if (m == NULL)
            throw ndSystemException(__PRETTY_FUNCTION__, "new pthread_mutex_t", ENOMEM);
        if ((rc = pthread_mutex_init(m, NULL)) != 0)
            throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_init", rc);
        bucket_lock.push_back(m);
    }

    nd_dprintf("Created %lu flow map buckets.\n", buckets);
}

ndFlowMap::~ndFlowMap()
{
    for (size_t i = 0; i < buckets; i++) {
        pthread_mutex_lock(bucket_lock[i]);

        for (auto it = bucket[i]->begin(); it != bucket[i]->end(); it++)
            delete it->second;

        delete bucket[i];

        pthread_mutex_unlock(bucket_lock[i]);
        pthread_mutex_destroy(bucket_lock[i]);

        delete bucket_lock[i];
    }

    bucket.clear();
    bucket_lock.clear();
}

ndFlow *ndFlowMap::Lookup(const string &digest, bool acquire_lock)
{
    ndFlow *f = NULL;
    size_t b = HashToBucket(digest);
    int rc = pthread_mutex_lock(bucket_lock[b]);
    if (rc != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_lock", rc);

    nd_dprintf("%s: bucket[%03lu]: locked\n", __PRETTY_FUNCTION__, b);

    auto fi = bucket[b]->find(digest);
    if (fi != bucket[b]->end()) {
        fi->second->tickets++;
        f = fi->second;
    }

    if (! acquire_lock) {
        if (pthread_mutex_unlock(bucket_lock[b]) == 0)
            nd_dprintf("%s: bucket[%03lu]: UNlocked\n", __PRETTY_FUNCTION__, b);
    }

    return f;
}

ndFlow *ndFlowMap::Insert(const string &digest, ndFlow *flow, bool unlocked)
{
    ndFlow *f = NULL;
    size_t b = HashToBucket(digest);
    if (! unlocked) {
        int rc = pthread_mutex_lock(bucket_lock[b]);
        if (rc != 0)
            throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_lock", rc);
        nd_dprintf("%s: bucket[%03lu]: locked\n", __PRETTY_FUNCTION__, b);
    }

    nd_flow_pair fp(digest, flow);
    nd_flow_insert fi = bucket[b]->insert(fp);

    if (fi.second == false)
        f = fi.first->second;
    else
        fi.first->second->tickets++;

    if (! unlocked) {
        if (pthread_mutex_unlock(bucket_lock[b]) == 0)
            nd_dprintf("%s: bucket[%03lu]: UNlocked\n", __PRETTY_FUNCTION__, b);
    }

    return f;
}

bool ndFlowMap::Delete(const string &digest)
{
    bool deleted = false;
    size_t b = HashToBucket(digest);
    int rc = pthread_mutex_lock(bucket_lock[b]);
    if (rc != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_lock", rc);
    nd_dprintf("%s: bucket[%03lu]: locked\n", __PRETTY_FUNCTION__, b);

    auto fi = bucket[b]->find(digest);
    if (fi != bucket[b]->end()) {
        deleted = true;
        bucket[b]->erase(fi);
    }

    if (pthread_mutex_unlock(bucket_lock[b]) == 0)
        nd_dprintf("%s: bucket[%03lu]: UNlocked\n", __PRETTY_FUNCTION__, b);

    return deleted;
}

nd_flow_map *ndFlowMap::Acquire(size_t b)
{
    if (b >= buckets)
        throw ndSystemException(__PRETTY_FUNCTION__, "bucket", EINVAL);

    int rc = pthread_mutex_lock(bucket_lock[b]);
    if (rc != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_lock", rc);

    nd_dprintf("%s: bucket[%03lu]: locked\n", __PRETTY_FUNCTION__, b);

    return bucket[b];
}

const nd_flow_map *ndFlowMap::AcquireConst(size_t b) const
{
    if (b >= buckets)
        throw ndSystemException(__PRETTY_FUNCTION__, "bucket", EINVAL);

    int rc = pthread_mutex_lock(bucket_lock[b]);
    if (rc != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_lock", rc);

    nd_dprintf("%s: bucket[%03lu]: locked\n", __PRETTY_FUNCTION__, b);

    return (const nd_flow_map *)bucket[b];
}

void ndFlowMap::Release(size_t b) const
{
    if (b >= buckets)
        throw ndSystemException(__PRETTY_FUNCTION__, "bucket", EINVAL);

    int rc = pthread_mutex_unlock(bucket_lock[b]);
    if (rc != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_lock", rc);

    nd_dprintf("%s: bucket[%03lu]: UNlocked\n", __PRETTY_FUNCTION__, b);
}

void ndFlowMap::Release(const string &digest) const
{
    Release(HashToBucket(digest));
}

#ifndef _ND_LEAN_AND_MEAN
void ndFlowMap::DumpBucketStats(void)
{
    for (size_t i = 0; i < buckets; i++) {
        int rc = pthread_mutex_trylock(bucket_lock[i]);
        if (rc != EBUSY)
            throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_lock", rc);

        if (rc == 0) {
            nd_dprintf("ndFlowMap: %4u: %u flow(s).\n", i, bucket[i]->size());
            pthread_mutex_unlock(bucket_lock[i]);
        }
        else
            nd_dprintf("ndFlowMap: %4u: locked.\n", i);
    }
}
#endif

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
