// Netify Agent
// Copyright (C) 2015-2021 eGloo Incorporated <http://www.egloo.ca>
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

#include <libipset/ipset.h>

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

bool ndCategory::Load(void)
{
    json j;
    string filename(ND_PERSISTENT_STATEDIR "/netify-categories.json");

    ifstream ifs(filename);
    if (! ifs.is_open()) {
        nd_printf("Error opening categories: %s: %s\n",
            filename.c_str(), strerror(ENOENT));
        return false;
    }

    try {
        ifs >> j;
    }
    catch (exception &e) {
        nd_printf("Error loading categories: %s: JSON parse error\n",
            filename.c_str());
        nd_dprintf("%s: %s\n", filename.c_str(), e.what());

        return false;
    }

    last_update = (time_t)(j["last_update"].get<unsigned>());

    auto apps_index = j.find("application_index");

    if (apps_index != j.end()) {
        apps.clear();
        auto obj = (*apps_index).get<json::object_t>();

        for (auto &kvp : obj) {
            for (auto k = kvp.second.begin(); k != kvp.second.end(); k++) {
                auto i = apps.find(kvp.first);
                if (i == apps.end()) {
                    apps.insert(
                        nd_name_lookup_pair(kvp.first, { (*k).get<unsigned>() })
                    );
                }
                else {
                    (*i).second.insert((*k).get<unsigned>());
                }
            }
        }
    }

    auto protos_index = j.find("protocol_index");

    if (protos_index != j.end()) {
        protos.clear();
        auto obj = (*protos_index).get<json::object_t>();

        for (auto &kvp : obj) {
            for (auto k = kvp.second.begin(); k != kvp.second.end(); k++) {
                auto i = protos.find(kvp.first);
                if (i == protos.end()) {
                    protos.insert(
                        nd_name_lookup_pair(kvp.first, { (*k).get<unsigned>() })
                    );
                }
                else {
                    (*i).second.insert((*k).get<unsigned>());
                }
            }
        }
    }

    Dump("Loaded");

    return true;
}

bool ndCategory::Save(void)
{
    json j;
    string filename(ND_PERSISTENT_STATEDIR "/netify-categories.json");

    try {
        j["last_update"] = time(NULL);
        j["application_index"] = apps;
        j["protocol_index"] = protos;
    } catch (exception &e) {
        nd_printf("Error JSON encoding categories: %s\n",
            filename.c_str());
        nd_dprintf("%s: %s\n", filename.c_str(), e.what());

        return false;
    }

    ofstream ofs(filename);
    if (! ofs.is_open()) {
        nd_printf("Error opening categories: %s: %s\n",
            filename.c_str(), strerror(ENOENT));
        return false;
    }

    try {
        ofs << j;
    }
    catch (exception &e) {
        nd_printf("Error saving categories: %s: JSON parse error\n",
            filename.c_str());
        nd_dprintf("%s: %s\n", filename.c_str(), e.what());

        return false;
    }

    return true;
}

void ndCategory::Dump(const string &oper)
{
    unsigned total = 0;

    for (auto i = apps.begin(); i != apps.end(); i++) {
        unsigned count = 0;
        for (auto j = i->second.begin(); j != i->second.end(); j++)
            count++;
        nd_dprintf("Application category: %s: %u ID(s).\n",
            i->first.c_str(), count);
        total += count;
    }

    nd_printf("%s %u applications across %u categories.\n",
        oper.c_str(), total, apps.size());

    total = 0;

    for (auto i = protos.begin(); i != protos.end(); i++) {
        unsigned count = 0;
        for (auto j = i->second.begin(); j != i->second.end(); j++)
            count++;
        nd_dprintf("Protocol category: %s: %u ID(s).\n",
            i->first.c_str(), count);
        total += count;
    }

    nd_printf("%s %u protocols across %u categories.\n",
        oper.c_str(), total, protos.size());
}

void ndCategory::Parse(ndCategoryType type, json &jdata)
{
    string key;
    nd_name_lookup *index = NULL;

    if (type == ndCAT_APP) {
        index = &apps;
        key = "application_category";
    }
    else if (type == ndCAT_PROTO) {
        index = &protos;
        key = "protocol_category";
    }
    else {
        nd_dprintf("Unknown category type: %u\n", type);
        return;
    }

    for (auto it = jdata.begin(); it != jdata.end(); it++) {

        auto it_cat = it->find(key);

        if (it_cat == it->end()) continue;

        unsigned id = (*it)["id"].get<unsigned>();
        string tag = (*it_cat)["tag"].get<string>();
        string label = (*it_cat)["label"].get<string>();

        transform(label.begin(), label.end(), label.begin(),
            [](unsigned char c){ return tolower(c); }
        );

        auto it_entry = index->find(label);
        if (it_entry == index->end())
            index->insert(nd_name_lookup_pair(label, { id }));
        else
            it_entry->second.insert(id);

        if (tag == label) continue;

        it_entry = index->find(tag);
        if (it_entry == index->end())
            index->insert(nd_name_lookup_pair(tag, { id }));
        else
            it_entry->second.insert(id);
    }
}

bool ndCategory::Lookup(ndCategoryType type, const string &name, unsigned id)
{
    string search(name);
    transform(search.begin(), search.end(), search.begin(),
        [](unsigned char c){ return tolower(c); }
    );

    nd_name_lookup::iterator i;

    if (type == ndCAT_APP) {
        i = apps.find(search);
        if (i == apps.end()) return false;
    }
    else if (type == ndCAT_PROTO) {
        i = protos.find(search);
        if (i == protos.end()) return false;
    }
    else return false;

    auto j = i->second.find(id);
    if (j == i->second.end()) return false;

    return true;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
