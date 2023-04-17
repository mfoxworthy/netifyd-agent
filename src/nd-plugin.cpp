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
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <atomic>
#include <regex>
#include <mutex>
#include <bitset>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <dlfcn.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

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
#include "nd-thread.h"
#include "nd-risks.h"
#include "nd-serializer.h"
#include "nd-packet.h"
#include "nd-json.h"
#include "nd-util.h"
#include "nd-addr.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-apps.h"
#include "nd-protos.h"
#include "nd-category.h"
#include "nd-flow.h"
#include "nd-flow-map.h"
#include "nd-plugin.h"

const map<ndPlugin::ndPluginType, string> ndPlugin::types = {
    // XXX: Keep in sync with ndPluginType enum
    make_pair(ndPlugin::TYPE_SINK, "sink"),
    make_pair(ndPlugin::TYPE_DETECTION, "detection"),
    make_pair(ndPlugin::TYPE_STATS, "stats"),
};

ndPlugin::ndPlugin(const string &tag)
    : ndThread(tag, -1), type(TYPE_BASE)
{
    nd_dprintf("Plugin initialized: %s\n", tag.c_str());
}

ndPlugin::~ndPlugin()
{
    nd_dprintf("Plugin destroyed: %s\n", tag.c_str());
}

ndPluginSink::ndPluginSink(const string &tag)
    : ndPlugin(tag) { }

ndPluginSink::~ndPluginSink()
{
    nd_dprintf("Plugin sink destroyed: %s\n", tag.c_str());
}

ndPluginDetection::ndPluginDetection(const string &tag)
    : ndPlugin(tag)
{
    type = ndPlugin::TYPE_DETECTION;
    nd_dprintf("Plugin detection initialized: %s\n", tag.c_str());
}

ndPluginDetection::~ndPluginDetection()
{
    nd_dprintf("Plugin detection destroyed: %s\n", tag.c_str());
}

ndPluginStats::ndPluginStats(const string &tag)
    : ndPlugin(tag)
{
    type = ndPlugin::TYPE_STATS;
    nd_dprintf("Plugin detection initialized: %s\n", tag.c_str());
}

ndPluginStats::~ndPluginStats()
{
    nd_dprintf("Plugin detection destroyed: %s\n", tag.c_str());
}

ndPluginLoader::ndPluginLoader(const string &so_name, const string &tag)
    : so_name(so_name), so_handle(NULL)
{
    so_handle = dlopen(so_name.c_str(), RTLD_NOW);
    if (so_handle == NULL) throw ndPluginException(tag, dlerror());

    char *dlerror_string;
    ndPlugin *(*ndPluginInit)(const string &);

    dlerror();
    *(void **) (&ndPluginInit) = dlsym(so_handle, "ndPluginInit");

    if ((dlerror_string = dlerror()) != NULL) {
        dlclose(so_handle);
        so_handle = NULL;
        throw ndPluginException(tag, dlerror_string);
    }

    plugin = (*ndPluginInit)(tag);
    if (plugin == NULL) {
        dlclose(so_handle);
        so_handle = NULL;
        throw ndPluginException(tag, "ndPluginInit");
    }

    nd_dprintf("Plugin loaded: %s: %s\n", tag.c_str(), so_name.c_str());
}

ndPluginLoader::~ndPluginLoader()
{
    nd_dprintf("Plugin dereferenced: %s\n", so_name.c_str());
    if (so_handle != NULL) dlclose(so_handle);
}

ndPluginManager::~ndPluginManager()
{
    for (auto &l : plugins) {
        for (auto &p : l.second)
            p->GetPlugin()->Terminate();
    }

    for (auto &l : plugins) {
        for (auto &p : l.second) {
            delete p->GetPlugin();
            delete p;
        }
    }

    plugins.clear();
}

void ndPluginManager::Load(ndPlugin::ndPluginType type, bool create)
{
    for (auto &t : ndPlugin::types) {
        const map<string, string> *conf_plugins = nullptr;

        if (type != ndPlugin::TYPE_BASE && type != t.first)
            continue;

        switch (t.first) {
        case ndPlugin::TYPE_SINK:
            conf_plugins = &ndGC.plugin_sinks;
            break;
        case ndPlugin::TYPE_DETECTION:
            conf_plugins = &ndGC.plugin_detections;
            break;
        case ndPlugin::TYPE_STATS:
            conf_plugins = &ndGC.plugin_stats;
            break;
        default:
            break;
        }

        if (conf_plugins == nullptr) continue;

        for (auto &i : *conf_plugins) {
            ndPluginLoader *loader = nullptr;

            try {
                loader = new ndPluginLoader(i.second, i.first);

                if (loader->GetPlugin()->GetType() != t.first)
                    throw ndPluginException(i.first, "wrong type");

                if (create)
                    loader->GetPlugin()->Create();
            }
            catch (ndPluginException &e) {
                nd_printf("Error loading %s plugin: %s\n",
                    t.second.c_str(), e.what()
                );
                if (loader != nullptr) {
                    if (loader->GetPlugin() != nullptr)
                        delete loader->GetPlugin();
                    delete loader;
                }
                throw e;
            }
            catch (ndThreadException &e) {
                nd_printf("Error starting %s plugin: %s %s: %s\n",
                    t.second.c_str(), i.first.c_str(),
                    i.second.c_str(), e.what()
                );
                if (loader != nullptr) {
                    if (loader->GetPlugin() != nullptr)
                        delete loader->GetPlugin();
                    delete loader;
                }
                throw e;
            }
            catch (exception &e) {
                nd_printf("Unknown error loading %s plugin: %s\n",
                    t.second.c_str(), e.what()
                );
                if (loader != nullptr) {
                    if (loader->GetPlugin() != nullptr)
                        delete loader->GetPlugin();
                    delete loader;
                }
                throw e;
            }

            auto pl = plugins.find(t.first);

            if (pl != plugins.end())
                pl->second.push_back(loader);
            else {
                vector<ndPluginLoader *> v = { loader };
                plugins.insert(make_pair(t.first, v));
            }
        }
    }
}

bool ndPluginManager::Create(ndPlugin::ndPluginType type)
{
    for (auto &t : ndPlugin::types) {
        auto pl = plugins.find(t.first);

        if (pl == plugins.end()) continue;

        for (auto &p : pl->second) {
            if (type != ndPlugin::TYPE_BASE && type != t.first)
                continue;

            try {
                p->GetPlugin()->Create();
            }
            catch (ndPluginException &e) {
                nd_printf("Error creating %s plugin: %s\n",
                    t.second.c_str(), e.what()
                );
                return false;
            }
            catch (ndThreadException &e) {
                nd_printf("Error starting %s plugin: %s: %s\n",
                    t.second.c_str(),
                    p->GetPlugin()->GetTag().c_str(),
                    e.what()
                );
                return false;
            }
        }
    }

    return true;
}

void ndPluginManager::Reap(ndPlugin::ndPluginType type)
{
    for (auto &t : ndPlugin::types) {
        if (type != ndPlugin::TYPE_BASE && type != t.first)
            continue;

        auto pl = plugins.find(t.first);
        if (pl == plugins.end()) continue;

        for (vector<ndPluginLoader *>::iterator p = pl->second.begin();
            p != pl->second.end(); ) {

            if (! (*p)->GetPlugin()->HasTerminated()) {
                p++;
                continue;
            }

            nd_printf("WARNING: Plugin exited abnormally: %s: %s\n",
                (*p)->GetPlugin()->GetTag().c_str(),
                (*p)->GetObjectName().c_str()
            );

            delete (*p)->GetPlugin();
            delete (*p);

            p = pl->second.erase(p);
        }
    }
}

void ndPluginManager::BroadcastEvent(ndPlugin::ndPluginType type,
    ndPlugin::ndPluginEvent event, void *param)
{
    for (auto &t : ndPlugin::types) {

        if (type != ndPlugin::TYPE_BASE && type != t.first)
            continue;

        auto pl = plugins.find(t.first);
        if (pl == plugins.end()) continue;

        for (auto &p : pl->second) {
            p->GetPlugin()->ProcessEvent(event, param);
        }
    }
}

void ndPluginManager::BroadcastDetectionEvent(
    ndPluginDetection::ndDetectionEvent event, ndFlow *flow)
{
    auto pl = plugins.find(ndPlugin::TYPE_DETECTION);

    if (pl == plugins.end()) return;

    for (auto &p : pl->second) {
        reinterpret_cast<ndPluginDetection *>(
            p->GetPlugin()
        )->ProcessFlow(event, flow);
    }
}

void ndPluginManager::GetStatus(json &status)
{
}

void ndPluginManager::DumpVersions(ndPlugin::ndPluginType type)
{
    for (auto &t : ndPlugin::types) {
        if (type != ndPlugin::TYPE_BASE && type != t.first)
            continue;

        auto pl = plugins.find(t.first);
        if (pl == plugins.end()) continue;

        for (auto &p : pl->second) {
            string version;
            p->GetPlugin()->GetVersion(version);

            fprintf(stderr, "%16s: %s: v%s\n",
                p->GetPlugin()->GetTag().c_str(),
                p->GetObjectName().c_str(),
                (version.empty()) ? "?.?.?" : version.c_str()
            );
        }
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
