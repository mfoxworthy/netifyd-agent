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
#include "nd-category.h"
#include "nd-protos.h"
#include "nd-flow.h"
#include "nd-flow-map.h"
#include "nd-flow-parser.h"
#include "nd-base64.h"

//#define _ND_APPS_DEBUG    1

ndApplications *nd_apps = NULL;

typedef radix_tree<ndRadixNetworkEntry<32>, nd_app_id_t> nd_rn4_app;
typedef radix_tree<ndRadixNetworkEntry<128>, nd_app_id_t> nd_rn6_app;

ndApplications::ndApplications()
    : stats{ 0 }, app_networks4(NULL), app_networks6(NULL)
{
    Reset();
}

ndApplications::~ndApplications()
{
    Reset(true);
}

bool ndApplications::Load(const string &filename)
{
    stats.ac = stats.dc = stats.nc = stats.sc = stats.xc = 0;

    ifstream ifs(filename);

    if (! ifs.is_open()) return false;

    unique_lock<mutex> ul(lock);

    Reset();

    string line;
    while (getline(ifs, line)) {
        nd_ltrim(line);
        if (line.empty() || line[0] == '#') continue;

        size_t p;
        if ((p = line.find_first_of(":")) == string::npos) continue;

        string type = line.substr(0, p);

        if (type != "app" && type != "dom" &&
            type != "net" && type != "nsd" && type != "xfm") continue;

        line = line.substr(p + 1);

        if (type == "app" || type == "dom" || type == "net") {
            if ((p = line.find_first_of(":")) == string::npos) continue;
            nd_app_id_t id = (nd_app_id_t)strtoul(
                line.substr(0, p).c_str(), NULL, 0
            );

            if (type == "app" && apps.find(id) == apps.end()) {
                if (AddApp(id, line.substr(p + 1)) != nullptr)
                    stats.ac++;
            }
            else if (type == "dom") {
                if (AddDomain(id, line.substr(p + 1))) stats.dc++;
            }
            else if (type == "net") {
                if (AddNetwork(id, line.substr(p + 1))) stats.nc++;
            }
        }
        else if (type == "xfm") {
            if ((p = line.find_first_of(":")) == string::npos) continue;
            if (AddDomainTransform(line.substr(0, p), line.substr(p + 1)))
                stats.xc++;
        }
        else if (type == "nsd") {
            if ((p = line.find_last_of(":")) == string::npos) continue;

            string expr = line.substr(p + 1);
            line = line.substr(0, p);
            if ((p = line.find_last_of(":")) == string::npos) continue;

            signed pid = (signed)strtol(
                line.substr(p + 1).c_str(), NULL, 0
            );

            line = line.substr(0, p);
            signed aid = (signed)strtol(
                line.c_str(), NULL, 0
            );

            if (AddSoftDissector(aid, pid, expr)) stats.sc++;
        }
    }

    if (stats.ac > 0) {
        nd_dprintf("Loaded %u apps, %u domains, %u networks, %u soft-dissectors, %u transforms.\n",
            stats.ac, stats.dc, stats.nc, stats.sc, stats.xc
        );
    }

    return (stats.ac > 0 && (stats.ac > 0 || stats.nc > 0));
}

bool ndApplications::LoadLegacy(const string &filename)
{
    size_t ac = 0, dc = 0, nc = 0, xc = 0;

    ifstream ifs(filename);

    if (! ifs.is_open()) return false;

    unique_lock<mutex> ul(lock);

    Reset();

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

        nd_app_id_t app_id = (nd_app_id_t)strtoul(
            app.substr(0, p).c_str(), NULL, 0
        );

        string app_tag = app.substr(p + 1);
        nd_trim(app_tag);

        if (apps.find(app_id) == apps.end()) {
            if (AddApp(app_id, app_tag) != nullptr) ac++;
            else return false;
        }

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

                if (AddDomain(app_id, domain)) dc++;
            }
            else if (type == "ip") {
                string cidr = entry.substr(p + 1);
                nd_trim(cidr);

                if (AddNetwork(app_id, cidr)) nc++;
            }
        }
    }

    if (ac > 0) {
        nd_dprintf("Loaded [legacy] %u apps, %u domains, %u networks, %u transforms.\n",
            ac, dc, nc, xc
        );
    }

    return (ac > 0 && (ac > 0 || nc > 0));
}

bool ndApplications::Save(const string &filename)
{
#ifndef _ND_LEAN_AND_MEAN
    size_t nc = 0;

    ofstream ofs(filename, ofstream::trunc);

    if (! ofs.is_open()) return false;

    unique_lock<mutex> ul(lock);

    for (auto &it : apps)
        ofs << "app:" << it.first << ":" << it.second->tag << endl;
    for (auto &it : domains)
        ofs << "dom:" << it.second << ":" << it.first << endl;
    nd_rn4_app *rn4 = static_cast<nd_rn4_app *>(app_networks4);
    for (auto &it : (*rn4)) {
        string ip;
        if (it.first.GetString(ip)) {
            ofs << "net:" << it.second << ":" << ip << endl;
            nc++;
        }
    }
    nd_rn6_app *rn6 = static_cast<nd_rn6_app *>(app_networks6);
    for (auto &it : (*rn6)) {
        string ip;
        if (it.first.GetString(ip)) {
            ofs << "net:" << it.second << ":" << ip << endl;
            nc++;
        }
    }
    for (auto &it : domain_xforms)
        ofs << "xfm:" << it.first << ":" << it.second.second << endl;

    nd_dprintf("Exported %u apps, %u domains, %u networks, %u transforms.\n",
        apps.size(), domains.size(), nc, domain_xforms.size()
    );

    return true;
#else
    nd_printf("Sorry, this feature was disabled (embedded).\n");
    return false;
#endif // _ND_LEAN_AND_MEAN
}

nd_app_id_t ndApplications::Find(const string &domain)
{
    unique_lock<mutex> ul(lock);

    vector<string> search;

    if (! domain.empty()) {
        for (auto &rx : domain_xforms) {
            string result = regex_replace(
                domain, (*rx.second.first), rx.second.second
            );
            if (result.size())
                search.push_back(result);
        }

        if (search.empty())
            search.push_back(domain);
    }

    for (auto &it : search) {

        for (size_t p = it.find('.'); ! it.empty(); p = it.find('.')) {

            if (p == string::npos &&
                tlds.find(it) == tlds.end()) break;

            auto it_domain = domains.find(it);
            if (it_domain != domains.end()) return it_domain->second;

            if (p == string::npos) break;

            it = it.substr(p + 1);
        }
    }

    return ND_APP_UNKNOWN;
}

nd_app_id_t ndApplications::Find(const ndAddr &addr)
{
    if (! addr.IsValid() || ! addr.IsIP())
        return ND_APP_UNKNOWN;

    if (addr.IsIPv4()) {
        ndRadixNetworkEntry<32> entry;
        if (ndRadixNetworkEntry<32>::CreateQuery(entry, addr)) {

            unique_lock<mutex> ul(lock);

            nd_rn4_app::iterator it;
            nd_rn4_app *rn4 = static_cast<nd_rn4_app *>(app_networks4);
            if ((it = rn4->longest_match(entry)) != rn4->end())
                return it->second;
        }
    }

    if (addr.IsIPv6()) {
        ndRadixNetworkEntry<128> entry;
        if (ndRadixNetworkEntry<128>::CreateQuery(entry, addr)) {

            unique_lock<mutex> ul(lock);

            nd_rn6_app::iterator it;
            nd_rn6_app *rn6 = static_cast<nd_rn6_app *>(app_networks6);
            if ((it = rn6->longest_match(entry)) != rn6->end())
                return it->second;
        }
    }

    return ND_APP_UNKNOWN;
}

const char *ndApplications::Lookup(nd_app_id_t id)
{
    unique_lock<mutex> ul(lock);

    auto it = apps.find(id);
    if (it != apps.end()) return it->second->tag.c_str();
    return "Unknown";
}

nd_app_id_t ndApplications::Lookup(const string &tag)
{
    unique_lock<mutex> ul(lock);

    auto it = app_tags.find(tag);
    if (it != app_tags.end()) return it->second->id;
    return ND_APP_UNKNOWN;
}

bool ndApplications::Lookup(const string &tag, ndApplication &app)
{
    unique_lock<mutex> ul(lock);

    auto it = app_tags.find(tag);
    if (it != app_tags.end()) {
        app = (*it->second);
        return true;
    }

    return false;
}

bool ndApplications::Lookup(nd_app_id_t id, ndApplication &app)
{
    unique_lock<mutex> ul(lock);

    auto it = apps.find(id);
    if (it != apps.end()) {
        app = (*it->second);
        return true;
    }
    return false;
}

void ndApplications::Reset(bool free_only)
{
    if (app_networks4 != nullptr) {
        nd_rn4_app *rn4 = static_cast<nd_rn4_app *>(app_networks4);
        delete rn4;
        app_networks4 = NULL;
    }

    if (app_networks6 != nullptr) {
        nd_rn6_app *rn6 = static_cast<nd_rn6_app *>(app_networks6);
        delete rn6;
        app_networks6 = NULL;
    }

    if (! free_only) {
        nd_rn4_app *rn4 = new nd_rn4_app;
        nd_rn6_app *rn6 = new nd_rn6_app;

        if (rn4 == nullptr || rn6 == nullptr) {
            throw ndSystemException(
                __PRETTY_FUNCTION__, "new", ENOMEM
            );
        }

        app_networks4 = static_cast<void *>(rn4);
        app_networks6 = static_cast<void *>(rn6);
    }

    for (auto &it : apps) delete it.second;

    for (auto &rx : domain_xforms) delete rx.second.first;

    apps.clear();
    app_tags.clear();
    domains.clear();
    domain_xforms.clear();
    soft_dissectors.clear();
}

void ndApplications::Get(nd_apps_t &apps_copy)
{
    apps_copy.clear();

    unique_lock<mutex> ul(lock);

    for (auto &app : apps)
        apps_copy.insert(make_pair(app.second->tag, app.first));
}

ndApplication *ndApplications::AddApp(
    nd_app_id_t id, const string &tag
) {
    auto it_id = apps.find(id);
    if (it_id != apps.end()) return it_id->second;

    auto it_tag = app_tags.find(tag);
    if (it_tag != app_tags.end()) return nullptr;

    ndApplication *app = new ndApplication(id, tag);

    if (app == nullptr) {
        throw ndSystemException(
            __PRETTY_FUNCTION__, "new ndApplication", ENOMEM
        );
    }

    apps.insert(make_pair(id, app));
    app_tags.insert(make_pair(tag, app));

    return app;
}

bool ndApplications::AddDomain(nd_app_id_t id, const string &domain)
{
    auto rc = domains.insert(make_pair(domain, id));
    if (domain.find_first_of(".") == string::npos)
        tlds.insert(domain);
    return rc.second;
}

bool ndApplications::AddDomainTransform(const string &search, const string &replace)
{
    if (search.size() == 0) return false;
    if (domain_xforms.find(search) != domain_xforms.end()) return false;

    try {
        regex *rx = new regex(
            search,
            regex::extended |
            regex::icase |
            regex::optimize
        );
        domain_xforms[search] = make_pair(rx, replace);
        return true;
    } catch (const regex_error &e) {
        string error;
        nd_regex_error(e, error);
        nd_printf("WARNING: Error compiling domain transform regex: %s: %s [%d]\n",
            search.c_str(), error.c_str(), e.code());
    } catch (bad_alloc &e) {
        throw ndSystemException(__PRETTY_FUNCTION__, "new regex", ENOMEM);
    }

    return false;
}

bool ndApplications::AddNetwork(
    nd_app_id_t id, const string &network
) {
    ndAddr addr(network);

    if (! addr.IsValid() || ! addr.IsIP()) {
        nd_printf("Invalid IPv4/6 network address: %s\n", network.c_str());
        return false;
    }

    try {
        if (addr.addr.ss.ss_family == AF_INET) {
            ndRadixNetworkEntry<32> entry;
            if (ndRadixNetworkEntry<32>::Create(entry, addr)) {
                nd_rn4_app *rn4 = static_cast<nd_rn4_app *>(app_networks4);
                (*rn4)[entry] = id;
                return true;
            }
        }
        else {
            ndRadixNetworkEntry<128> entry;
            if (ndRadixNetworkEntry<128>::Create(entry, addr)) {
                nd_rn6_app *rn6 = static_cast<nd_rn6_app *>(app_networks6);
                (*rn6)[entry] = id;
                return true;
            }
        }
    }
    catch (runtime_error &e) {
        nd_dprintf("Error adding network: %s: %s\n",
            network.c_str(), e.what());
    }

    return false;
}

bool ndApplications::AddSoftDissector(
    signed aid, signed pid, const string &encoded_expr)
{
    string decoded_expr = base64_decode(encoded_expr.c_str(), encoded_expr.size());

    if (aid < 0 && pid < 0) return false;

    nd_dprintf("%s: app: %d, proto: %d, expr: \"%s\"\n",
        __PRETTY_FUNCTION__, aid, pid, decoded_expr.c_str());

    soft_dissectors.push_back(
        ndSoftDissector(aid, pid, decoded_expr)
    );

    return true;
}

bool ndApplications::SoftDissectorMatch(
    const ndFlow *flow, ndFlowParser *parser, ndSoftDissector &match)
{
    unique_lock<mutex> ul(lock);

    for (auto &it : soft_dissectors) {
        try {
            if (! parser->Parse(flow, it.expr)) continue;
            match = it;
            return true;
        } catch (string &e) {
            nd_dprintf("%s: %s: %s\n", __PRETTY_FUNCTION__,
                it.expr.c_str(), e.c_str()
            );
        }
    }

    return false;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
