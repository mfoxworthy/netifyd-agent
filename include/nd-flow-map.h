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

#ifndef _ND_FLOW_MAP_H
#define _ND_FLOW_MAP_H

typedef unordered_map<string, ndFlow *> nd_flow_map;
typedef vector<nd_flow_map *> nd_flow_bucket;
typedef vector<pthread_mutex_t *> nd_flow_bucket_lock;
typedef pair<string, ndFlow *> nd_flow_pair;
typedef pair<nd_flow_map::iterator, bool> nd_flow_insert;

class ndFlowMap
{
public:
    ndFlowMap(size_t buckets = ND_FLOW_MAP_BUCKETS);
    virtual ~ndFlowMap();

    ndFlow *Lookup(const string &digest, bool acquire_lock = false);
    ndFlow *Insert(const string &digest, ndFlow *flow, bool unlocked = false);
    inline ndFlow *InsertUnlocked(const string &digest, ndFlow *flow) {
        return Insert(digest, flow, true);
    }

    bool Delete(const string &digest);

    nd_flow_map *Acquire(size_t b);
    const nd_flow_map *AcquireConst(size_t b) const;

    void Release(size_t b) const;
#if 0
    inline void Release(const string &digest) const {
        Release(HashToBucket(digest));
    }
#else
    void Release(const string &digest) const;
#endif
#ifndef _ND_LEAN_AND_MEAN
    void DumpBucketStats(void);
#endif

    inline size_t GetBuckets(void) const { return buckets; }

protected:
    unsigned HashToBucket(const string &digest) const {
        const char *p = digest.c_str();
        const uint64_t *b = (const uint64_t *)&p[0];
        return (*b % buckets);
    }

    size_t buckets;
    nd_flow_bucket bucket;
    nd_flow_bucket_lock bucket_lock;
};

#endif // _ND_FLOW_MAP_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
