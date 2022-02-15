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
#include <string>
#include <fstream>
#include <sstream>
#include <atomic>
#include <regex>
#include <iomanip>
#include <algorithm>
#include <cctype>

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

#include "nd-ndpi.h"
#include "nd-json.h"
#include "nd-thread.h"
#include "nd-util.h"
#include "nd-category.h"

extern nd_global_config nd_config;

bool ndCategories::Load(void)
{
    json j;

    ifstream ifs(nd_config.path_cat_config);
    if (! ifs.is_open()) {
        nd_printf("Error opening categories: %s: %s\n",
            nd_config.path_cat_config, strerror(ENOENT));
        return false;
    }

    try {
        ifs >> j;
    }
    catch (exception &e) {
        nd_printf("Error loading categories: %s: JSON parse error\n",
            nd_config.path_cat_config);
        nd_dprintf("%s: %s\n", nd_config.path_cat_config, e.what());

        return false;
    }

    last_update = (time_t)(j["last_update"].get<unsigned>());

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
            ci.second.tag = j[key + "_tag_index"].get<ndCategory::index_tag>();
            ci.second.index = j[key + "_index"].get<ndCategory::index_cat>();
        }
    }

    return true;
}

bool ndCategories::Load(ndCategoryType type, json &jdata)
{
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

        unsigned id = (*it)["id"].get<unsigned>();
        unsigned cid = (*it_cat)["id"].get<unsigned>();
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
            nd_config.path_cat_config);
        nd_dprintf("%s: %s\n", nd_config.path_cat_config, e.what());

        return false;
    }

    ofstream ofs(nd_config.path_cat_config);

    if (! ofs.is_open()) {
        nd_printf("Error opening categories: %s: %s\n",
            nd_config.path_cat_config, strerror(ENOENT));
        return false;
    }

    try {
        ofs << j;
    }
    catch (exception &e) {
        nd_printf("Error saving categories: %s: JSON parse error\n",
            nd_config.path_cat_config);
        nd_dprintf("%s: %s\n", nd_config.path_cat_config, e.what());

        return false;
    }

    return true;
}

void ndCategories::Dump(ndCategoryType type)
{
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

bool ndCategories::IsMember(ndCategoryType type, unsigned cat_id, unsigned id)
{
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

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
