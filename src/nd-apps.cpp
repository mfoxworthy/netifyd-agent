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

#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define __FAVOR_BSD 1
#include <netinet/ip.h>
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <arpa/inet.h>

#include <pcap/pcap.h>

#include <curl/curl.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#include "nd-json.h"
#include "nd-thread.h"
#include "nd-util.h"
#include "nd-apps.h"
#include "nd-protos.h"

template<size_t N>
bool operator<(const bitset<N> &x, const bitset<N> &y)
{
    for (int i = N-1; i >= 0; i--) {
        if (x[i] ^ y[i]) return y[i];
    }

    return false;
}

template<size_t N>
bitset<N> &operator-=(bitset<N> &x, const size_t y)
{
    bool borrow = false;
    bitset<N> const _y(y);

    for (size_t i = 0; i < N; i++) {
        if (borrow) {
            if (x[i]) {
                x[i] = _y[i];
                borrow = _y[i];
            }
            else {
                x[i] = ! _y[i];
                borrow = true;
            }
        }
        else {
            if (x[i]) {
                x[i] = ! _y[i];
                borrow = false;
            }
            else {
                x[i] = _y[i];
                borrow = _y[i];
            }
        }
    }

    return x;
}

template <size_t N>
class ndRadixNetworkEntry {
public:
    bitset<N> addr;
    size_t prefix_len;

    ndRadixNetworkEntry() : prefix_len(0) { }

    bool operator[] (int n) const {
        return addr[(N - 1) - n];
    }

    bool operator== (const ndRadixNetworkEntry &rhs) const {
        return prefix_len == rhs.prefix_len && addr == rhs.addr;
    }

    bool operator< (const ndRadixNetworkEntry &rhs) const {
        if (addr == rhs.addr)
            return prefix_len < rhs.prefix_len;
        else
            return addr < rhs.addr;
    }
};

// TODO: static?
template <size_t N>
ndRadixNetworkEntry<N> radix_substr(const ndRadixNetworkEntry<N> &entry, int offset, int length)
{
    bitset<N> mask;

    if (length == N)
        mask = 0;
    else
        mask = 1 << length;

    mask -= 1;
    mask <<= N - length - offset;

    ndRadixNetworkEntry<N> result;
    result.addr = (entry.addr & mask) << offset;
    result.prefix_len = length;

    return result;
}

template <size_t N>
ndRadixNetworkEntry<N> radix_join(const ndRadixNetworkEntry<N> &x, const ndRadixNetworkEntry<N> &y)
{
    ndRadixNetworkEntry<N> result;

    result.addr = x.addr;
    result.addr |= y.addr >> x.prefix_len;
    result.prefix_len = x.prefix_len + y.prefix_len;

    return result;
}

template <size_t N>
int radix_length(const ndRadixNetworkEntry<N> &entry)
{
    return (int)entry.prefix_len;
}

typedef radix_tree<ndRadixNetworkEntry<32>, nd_app_id_t> nd_rn4_t;
typedef radix_tree<ndRadixNetworkEntry<128>, nd_app_id_t> nd_rn6_t;

ndApplications::ndApplications()
{
    nd_rn4_t *rn4 = new nd_rn4_t;
    nd_rn6_t *rn6 = new nd_rn6_t;

    if (rn4 == nullptr || rn6 == nullptr) {
        // TODO: throw...
        return;
    }

    app_networks4 = static_cast<void *>(rn4);
    app_networks6 = static_cast<void *>(rn6);
}

ndApplications::~ndApplications()
{
    nd_rn4_t *rn4 = static_cast<nd_rn4_t *>(app_networks4);
    delete rn4;
    nd_rn6_t *rn6 = static_cast<nd_rn6_t *>(app_networks6);
    delete rn6;

    for (auto &it : apps) delete it.second;
}

bool ndApplications::Load(const string &filename)
{
    return false;
}

bool ndApplications::LoadLegacy(const string &filename)
{
    size_t records = 0;
    ifstream ifs(filename);

    if (! ifs.is_open()) return false;

    string line;
    while (getline(ifs, line)) {
        nd_trim(line);
        if (line.empty() || line[0] == '#') continue;

        size_t p;
        if ((p = line.find_last_of("@")) == string::npos) continue;

        stringstream entries(line.substr(0, p));

        string app = line.substr(p + 1);
        nd_trim(app);

        if ((p = app.find_first_of(".")) == string::npos) continue;

        string app_id = app.substr(0, p);
        nd_trim(app_id);

        string app_tag = app.substr(p + 1);
        nd_trim(app_tag);

        string entry;
        while (getline(entries, entry, ',')) {
            nd_trim(entry);

            if ((p = entry.find_first_of(":")) == string::npos)
                continue;

            string type = entry.substr(0, p);
            nd_trim(type);

            if (type == "host") {
                string domain = entry.substr(p + 1);
                nd_trim(domain);
                nd_trim(domain, '"');
                if (domain[0] != '^') continue;
                nd_ltrim(domain, '^');
                nd_rtrim(domain, '$');

                ndApplication *_app = AddApp(
                    (nd_app_id_t)strtoul(app_id.c_str(), NULL, 0),
                    app_tag);

                if (_app != nullptr) {
                    nd_dprintf("add app: %u %s, domain: %s\n",
                        _app->id, app_tag.c_str(), domain.c_str());

                    AddDomain(_app, domain);
                    records++;
                }
            }
            else if (type == "ip") {
                string cidr = entry.substr(p + 1);
                nd_trim(cidr);

                ndApplication *_app = AddApp(
                    (nd_app_id_t)strtoul(app_id.c_str(), NULL, 0),
                    app_tag);

                if (_app != nullptr) {
                    nd_dprintf("add app: %u %s, network: %s\n",
                        _app->id, app_tag.c_str(), cidr.c_str());

                    AddNetwork(_app, cidr);
                    records++;
                }
            }
        }
    }

    if (records > 0)
        nd_dprintf("Loaded %u application criteria.\n", records);

    return (records > 0);
}

nd_app_id_t ndApplications::Find(const string &domain)
{
    auto it = domains.find(domain);
    if (it != domains.end()) return it->second;

    size_t p = 0;
    string sub = domain;
    while ((p = sub.find_first_of(".")) != string::npos) {

        sub = sub.substr(p + 1);
        if (sub.find_first_of(".") == string::npos) break;

        it = domains.find(sub);
        if (it != domains.end()) return it->second;
    }

    return ND_APP_UNKNOWN;
}

nd_app_id_t ndApplications::Find(sa_family_t af, void *addr)
{
    in_addr *dst_addr;
    in6_addr *dst6_addr;

    switch (af) {
    case AF_INET:
        dst_addr = static_cast<in_addr *>(addr);
        break;
    case AF_INET6:
        dst6_addr = static_cast<in6_addr *>(addr);
        break;
    default:
        nd_printf("Invalid address family: %hu\n", af);
        return ND_APP_UNKNOWN;
    }

    if (af == AF_INET) {
        ndRadixNetworkEntry<32> entry;
        entry.prefix_len = 32;
        entry.addr = ntohl(dst_addr->s_addr);

        nd_rn4_t::iterator it;
        nd_rn4_t *rn4 = static_cast<nd_rn4_t *>(app_networks4);
        if ((it = rn4->longest_match(entry)) != rn4->end())
            return it->second;
    }
    else if (af == AF_INET6) {
        ndRadixNetworkEntry<128> entry;
        entry.prefix_len = 128;
        for (auto i = 0; i < 4; i++) {
            entry.addr |= ntohl(dst6_addr->s6_addr32[i]);
            if (i != 3) entry.addr <<= 32;
        }

        nd_rn6_t::iterator it;
        nd_rn6_t *rn6 = static_cast<nd_rn6_t *>(app_networks6);
        if ((it = rn6->longest_match(entry)) != rn6->end())
            return it->second;
    }

    return ND_APP_UNKNOWN;
}

const char *ndApplications::Lookup(nd_app_id_t id)
{
    auto it = apps.find(id);
    if (it != apps.end()) return it->second->tag.c_str();
    nd_dprintf("Lookup failed: ID: %u\n", id);
    return "ND_APP_UNKNOWN";
}

nd_app_id_t ndApplications::Lookup(const string &tag)
{
    auto it = app_tags.find(tag);
    if (it != app_tags.end()) return it->second->id;
    return ND_APP_UNKNOWN;
}

bool ndApplications::Lookup(const string &tag, ndApplication &app)
{
    auto it = app_tags.find(tag);
    if (it != app_tags.end()) {
        app = (*it->second);
        return true;
    }

    return false;
}

bool ndApplications::Lookup(nd_app_id_t id, ndApplication &app)
{
    auto it = apps.find(id);
    if (it != apps.end()) {
        app = (*it->second);
        return true;
    }
    return false;
}

ndApplication *ndApplications::AddApp(nd_app_id_t id, const string &tag)
{
    auto it_id = apps.find(id);
    if (it_id != apps.end()) return it_id->second;

    auto it_tag = app_tags.find(tag);
    if (it_tag != app_tags.end()) return nullptr;

    ndApplication *app = new ndApplication(id, tag);

    if (app == nullptr) return nullptr;

    apps.insert(make_pair(id, app));
    app_tags.insert(make_pair(tag, app));
}

void ndApplications::AddDomain(ndApplication *app, const string &domain)
{
    domains.insert(make_pair(domain, app->id));
}

void ndApplications::AddNetwork(ndApplication *app, const string &network)
{
    in_addr nw_addr;
    in6_addr nw6_addr;
    sa_family_t af = AF_UNSPEC;
    size_t shift, prefix_max = 0, prefix_len = 0;

    string addr;
    size_t p = string::npos;
    if ((p = network.find_first_of("/")) != string::npos) {
        addr = network.substr(0, p);
        prefix_len = (size_t)strtoul(
            network.substr(p + 1).c_str(), NULL, 0
        );
    }

    if (inet_pton(AF_INET, addr.c_str(), &nw_addr)) {
        af = AF_INET;
        prefix_max = 32;
    }
    else if (inet_pton(AF_INET6, addr.c_str(), &nw6_addr)) {
        af = AF_INET6;
        prefix_max = 128;
    }
    else {
        nd_printf("Invalid IPv4/6 network address: %s\n", addr.c_str());
        return;
    }

    if (prefix_len > prefix_max) {
        nd_printf("Invalid prefix length: > %u\n", prefix_max);
        return;
    }

    bitset<32> mask32;
    bitset<128> mask128;

    shift = prefix_max - prefix_len;
    if (shift < prefix_max) {
        if (prefix_max == 32) {
            mask32.set();
            for (auto i = 0; i < shift; i++) mask32.flip(i);
        }
        else {
            mask128.set();
            for (auto i = 0; i < shift; i++) mask128.flip(i);
        }
    }

    if (af == AF_INET) {
        ndRadixNetworkEntry<32> entry;
        entry.prefix_len = prefix_len;
        entry.addr = ntohl(nw_addr.s_addr);
        entry.addr &= mask32;

        nd_rn4_t *rn4 = static_cast<nd_rn4_t *>(app_networks4);
        (*rn4)[entry] = app->id;
    }
    else {
        ndRadixNetworkEntry<128> entry;
        entry.prefix_len = prefix_len;
        for (auto i = 0; i < 4; i++) {
            bitset<32> quad = ntohl(nw6_addr.s6_addr32[i]);
            entry.addr |= ntohl(nw6_addr.s6_addr32[i]);
            if (i != 3) entry.addr <<= 32;
        }
        entry.addr &= mask128;

        nd_rn6_t *rn6 = static_cast<nd_rn6_t *>(app_networks6);
        (*rn6)[entry] = app->id;
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4