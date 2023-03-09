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
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <mutex>

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

#include <pcap/pcap.h>

#include <curl/curl.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

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
#include "nd-category.h"

//#define _ND_LOG_DOMAINS   1

extern ndGlobalConfig nd_config;

ndCategories *nd_categories = NULL;
ndDomains *nd_domains = NULL;

bool ndCategories::Load(void)
{
    unique_lock<mutex> ul(lock);

    json jdata;

    ifstream ifs(nd_config.path_cat_config);
    if (! ifs.is_open()) {
        nd_printf("Error opening categories: %s: %s\n",
            nd_config.path_cat_config.c_str(), strerror(ENOENT));
        return false;
    }

    try {
        ifs >> jdata;
    }
    catch (exception &e) {
        nd_printf("Error loading categories: %s: JSON parse error\n",
            nd_config.path_cat_config.c_str());
        nd_dprintf("%s: %s\n", nd_config.path_cat_config.c_str(), e.what());

        return false;
    }

    last_update = (time_t)(jdata["last_update"].get<unsigned>());

    if (jdata.find("application_tag_index") == jdata.end() ||
        jdata.find("protocol_tag_index") == jdata.end())
        return LoadLegacy(jdata);

    for (auto &ci : categories) {
        string key;

        switch (ci.first) {
        case ndCAT_TYPE_APP:
            key = "application";
            break;
        case ndCAT_TYPE_PROTO:
            key = "protocol";
            break;
        default:
            break;
        }

        if (! key.empty()) {
            ci.second.tag = jdata[key + "_tag_index"].get<ndCategory::index_tag>();
            ci.second.index = jdata[key + "_index"].get<ndCategory::index_cat>();
        }
    }

    return true;
}

bool ndCategories::LoadLegacy(json &jdata) {
    nd_printf("Legacy category format detected: %s\n",
        nd_config.path_cat_config.c_str());

    for (auto &ci : categories) {
        string key;
        nd_cat_id_t id = 1;

        switch (ci.first) {
        case ndCAT_TYPE_APP:
            key = "application";
            break;
        case ndCAT_TYPE_PROTO:
            key = "protocol";
            break;
        default:
            break;
        }

        auto it = jdata.find(key + "_index");
        for (auto &it_kvp : it->get<json::object_t>()) {

            if (it_kvp.second.type() != json::value_t::array)
                continue;

            ci.second.tag[it_kvp.first] = id;
            ci.second.index[id] =
                it_kvp.second.get<ndCategory::set_id>();

            id++;
        }
    }

    return true;
}

bool ndCategories::Load(ndCategoryType type, json &jdata)
{
    unique_lock<mutex> ul(lock);

    auto ci = categories.find(type);

    if (ci == categories.end()) {
        nd_dprintf("%s: category type not found: %u\n", __PRETTY_FUNCTION__, type);
        return false;
    }

    string key;

    switch (type) {
    case ndCAT_TYPE_APP:
        key = "application_category";
        break;
    case ndCAT_TYPE_PROTO:
        key = "protocol_category";
        break;
    default:
        break;
    }

    for (auto it = jdata.begin(); it != jdata.end(); it++) {

        auto it_cat = it->find(key);
        if (it_cat == it->end()) continue;

        nd_cat_id_t id = (*it)["id"].get<unsigned>();
        nd_cat_id_t cid = (*it_cat)["id"].get<nd_cat_id_t>();
        string tag = (*it_cat)["tag"].get<string>();

        auto it_tag_id = ci->second.tag.find(tag);

        if (it_tag_id == ci->second.tag.end())
            ci->second.tag[tag] = cid;

        auto it_entry = ci->second.index.find(cid);

        if (it_entry == ci->second.index.end())
            ci->second.index.insert(ndCategory::index_cat_insert(cid, { id }));
        else
            it_entry->second.insert(id);
    }

    return true;
}

bool ndCategories::Save(void)
{
    unique_lock<mutex> ul(lock);

    json j;

    try {
        j["last_update"] = time(NULL);

        for (auto &ci : categories) {
            switch (ci.first) {
            case ndCAT_TYPE_APP:
                j["application_tag_index"] = ci.second.tag;
                j["application_index"] = ci.second.index;
                break;
            case ndCAT_TYPE_PROTO:
                j["protocol_tag_index"] = ci.second.tag;
                j["protocol_index"] = ci.second.index;
                break;
            default:
                break;
            }
        }
    } catch (exception &e) {
        nd_printf("Error JSON encoding categories: %s\n",
            nd_config.path_cat_config.c_str());
        nd_dprintf("%s: %s\n", nd_config.path_cat_config.c_str(), e.what());

        return false;
    }

    ofstream ofs(nd_config.path_cat_config);

    if (! ofs.is_open()) {
        nd_printf("Error opening categories: %s: %s\n",
            nd_config.path_cat_config.c_str(), strerror(ENOENT));
        return false;
    }

    try {
        ofs << j;
    }
    catch (exception &e) {
        nd_printf("Error saving categories: %s: JSON parse error\n",
            nd_config.path_cat_config.c_str());
        nd_dprintf("%s: %s\n", nd_config.path_cat_config.c_str(), e.what());

        return false;
    }

    return true;
}

void ndCategories::Dump(ndCategoryType type)
{
    unique_lock<mutex> ul(lock);

    for (auto &ci : categories) {
        if (type != ndCAT_TYPE_MAX && ci.first != type) continue;

        for (auto &li : ci.second.tag) {
            if (type != ndCAT_TYPE_MAX)
                printf("%6u: %s\n", li.second, li.first.c_str());
            else {
                string tag("unknown");

                switch (ci.first) {
                case ndCAT_TYPE_APP:
                    tag = "application";
                    break;
                case ndCAT_TYPE_PROTO:
                    tag = "protocol";
                    break;
                default:
                    break;
                }

                printf("%6u: %s: %s\n", li.second, tag.c_str(), li.first.c_str());
            }
        }
    }
}

bool ndCategories::IsMember(ndCategoryType type, nd_cat_id_t cat_id, unsigned id)
{
    unique_lock<mutex> ul(lock);
    auto ci = categories.find(type);

    if (ci == categories.end()) {
        nd_dprintf("%s: category type not found: %u\n", __PRETTY_FUNCTION__, type);
        return false;
    }

    auto mi = ci->second.index.find(cat_id);

    if (mi == ci->second.index.end()) return false;

    if (mi->second.find(id) == mi->second.end()) return false;

    return false;
}

bool ndCategories::IsMember(ndCategoryType type, const string &cat_tag, unsigned id)
{
    unique_lock<mutex> ul(lock);
    auto ci = categories.find(type);

    if (ci == categories.end()) {
        nd_dprintf("%s: category type not found: %u\n", __PRETTY_FUNCTION__, type);
        return false;
    }

    auto ti = ci->second.tag.find(cat_tag);

    if (ti == ci->second.tag.end()) return false;

    auto mi = ci->second.index.find(ti->second);

    if (mi == ci->second.index.end()) return false;

    if (mi->second.find(id) == mi->second.end()) return false;

    return true;
}

nd_cat_id_t ndCategories::Lookup(ndCategoryType type, unsigned id)
{
    if (type >= ndCAT_TYPE_MAX) return ND_CAT_UNKNOWN;

    unique_lock<mutex> ul(lock);

    for (auto &it : categories[type].index) {
        if (it.second.find(id) == it.second.end()) continue;
        return it.first;
    }

    return ND_CAT_UNKNOWN;
}

nd_cat_id_t ndCategories::LookupTag(ndCategoryType type, const string &tag)
{
    if (type >= ndCAT_TYPE_MAX) return ND_CAT_UNKNOWN;

    unique_lock<mutex> ul(lock);

    ndCategory::index_tag::const_iterator it = categories[type].tag.find(tag);
    if (it != categories[type].tag.end()) return it->second;

    return ND_CAT_UNKNOWN;
}

ndDomains::ndDomains()
{
    path_domains = nd_config.path_state_persistent + "/domains.d";
}

bool ndDomains::Load(void)
{
    unique_lock<mutex> ul(lock);

    ndCategories categories;
    categories.Load();

    if (! categories.GetTagIndex(ndCAT_TYPE_APP, index_tag)) return false;

    vector<string> files;
    if (! nd_scan_dotd(path_domains, files)) return false;

    domains.clear();

    // /etc/netify.d/domains.d/10-adult.txt
    // /etc/netify.d/domains.d/{pri}-{cat_tag}.txt

    for (auto &it : files) {
        size_t p1 = it.find_first_of("-");
        if (p1 == string::npos) {
            nd_dprintf("Rejecting domain file (wrong format; missing hyphen): %s\n",
                it.c_str());
            continue;
        }

        size_t p2 = it.find_last_of(".");
        if (p2 == string::npos) {
            nd_dprintf("Rejecting domain file (wrong format; missing extension): %s\n",
                it.c_str());
            continue;
        }

        string cat_tag = it.substr(p1 + 1, p2 - p1 - 1);

        auto tag = index_tag.find(cat_tag);
        if (tag == index_tag.end()) {
            nd_dprintf("Rejecting domain file (invalid category tag): %s\n",
                it.c_str());
            continue;
        }

        nd_dprintf("Loading custom %s domain file: %s\n",
            tag->first.c_str(), it.c_str());

        ifstream ifs(path_domains + "/" + it);

        if (! ifs.is_open()) {
            nd_printf("Error opening custom domain category file: %s\n", it.c_str());
            continue;
        }

        string domain;
        unordered_set<string> entries;
        while (ifs >> domain) entries.insert(domain);

        domains.insert(make_pair(tag->second, entries));

        nd_dprintf("Loaded %u %s domains from: %s\n",
            entries.size(), tag->first.c_str(), it.c_str()
        );
    }

    return true;
}

nd_cat_id_t ndDomains::Lookup(const string &domain)
{
    unique_lock<mutex> ul(lock);

    string search(domain);
    size_t p = string::npos;

    do {
        for (auto &it : domains) {
#ifdef _ND_LOG_DOMAINS
            nd_dprintf("%s: searching category %hu for: %s\n",
                __PRETTY_FUNCTION__, it.first, search.c_str()
            );
#endif
            if (it.second.find(search) != it.second.end()) {
#ifdef _ND_LOG_DOMAINS
                nd_dprintf("%s: found: %s\n",
                    __PRETTY_FUNCTION__, search.c_str());
#endif
                return it.first;
            }
        }

        if ((p = search.find_first_of(".")) != string::npos)
            search = search.substr(p + 1);
    }
    while (search.size() && p != string::npos);

    return ND_DOMAIN_UNKNOWN;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
