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

//#define _ND_LOG_PLUGIN_DEBUG    1

const map<ndPlugin::ndPluginType, string> ndPlugin::types = {
    // XXX: Keep in sync with ndPluginType enum
    make_pair(ndPlugin::TYPE_SINK, "sink"),
    make_pair(ndPlugin::TYPE_ENCODER, "encoder"),
};

ndPlugin::ndPlugin(ndPluginType type, const string &tag)
    : ndThread(tag, -1), type(type)
{
#ifdef _ND_LOG_PLUGIN_DEBUG
    nd_dprintf("Plugin created: %s\n", tag.c_str());
#endif
}

ndPlugin::~ndPlugin()
{
#ifdef _ND_LOG_PLUGIN_DEBUG
    nd_dprintf("Plugin destroyed: %s\n", tag.c_str());
#endif
}

ndPluginSink::ndPluginSink(const string &tag)
    : ndPlugin(ndPlugin::TYPE_SINK, tag)
{
#ifdef _ND_LOG_PLUGIN_DEBUG
    nd_dprintf("Sink plugin created: %s\n", tag.c_str());
#endif
}

ndPluginSink::~ndPluginSink()
{
#ifdef _ND_LOG_PLUGIN_DEBUG
    nd_dprintf("Sink plugin destroyed: %s\n", tag.c_str());
#endif
}

ndPluginEncoder::ndPluginEncoder(const string &tag)
    : ndPlugin(ndPlugin::TYPE_ENCODER, tag)
{
#ifdef _ND_LOG_PLUGIN_DEBUG
    nd_dprintf("Encoder plugin created: %s\n", tag.c_str());
#endif
}

ndPluginEncoder::~ndPluginEncoder()
{
#ifdef _ND_LOG_PLUGIN_DEBUG
    nd_dprintf("Encoder plugin destroyed: %s\n", tag.c_str());
#endif
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
    if (so_handle != NULL) {
        dlclose(so_handle);
#ifdef _ND_LOG_PLUGIN_DEBUG
        nd_dprintf("Plugin dereferenced: %s\n", so_name.c_str());
#endif
    }
}

ndPluginManager::~ndPluginManager()
{
    unique_lock<mutex> ul(lock);

    for (auto &p : sinks)
        p.second->GetPlugin()->Terminate();

    for (auto &p : sinks) {
        delete p.second->GetPlugin();
        delete p.second;
    }

    for (auto &p : encoders)
        p.second->GetPlugin()->Terminate();

    for (auto &p : encoders) {
        delete p.second->GetPlugin();
        delete p.second;
    }

    sinks.clear();
    encoders.clear();
}

void ndPluginManager::Load(ndPlugin::ndPluginType type, bool create)
{
    unique_lock<mutex> ul(lock);

    for (auto &t : ndPlugin::types) {
        if (type != ndPlugin::TYPE_BASE && type != t.first)
            continue;

        const map<string, string> *plugins = nullptr;

        switch (t.first) {
        case ndPlugin::TYPE_SINK:
            plugins = &ndGC.plugin_sinks;
            break;
        case ndPlugin::TYPE_ENCODER:
            plugins = &ndGC.plugin_encoders;
            break;
        default:
            break;
        }

        if (plugins == nullptr) continue;

        for (auto &i : *plugins) {
            ndPluginLoader *loader = nullptr;

            loader = new ndPluginLoader(i.second, i.first);

            if (loader->GetPlugin()->GetType() != t.first)
                throw ndPluginException(i.first, "wrong type");

            if (create)
                loader->GetPlugin()->Create();

            map_plugin *mp = nullptr;

            switch (t.first) {
            case ndPlugin::TYPE_SINK:
                mp = &sinks;
                break;
            case ndPlugin::TYPE_ENCODER:
                mp = &encoders;
                break;
            default:
                throw ndPluginException(
                    i.first, "invalid type"
                );
                break;
            }

            auto pl = mp->find(t.second);

            if (pl != mp->end()) {
                throw ndPluginException(i.first,
                    "duplicate plugin tag"
                );
            }

            if (! mp->insert(make_pair(i.first, loader)).second) {
                throw ndPluginException(i.first,
                    "failed to insert loader"
                );
            }
        }
    }
}

bool ndPluginManager::Create(ndPlugin::ndPluginType type)
{
    unique_lock<mutex> ul(lock);

    for (auto &t : ndPlugin::types) {
        if (type != ndPlugin::TYPE_BASE && type != t.first)
            continue;

        map_plugin *mp = nullptr;

        switch (t.first) {
        case ndPlugin::TYPE_SINK:
            mp = &sinks;
            break;
        case ndPlugin::TYPE_ENCODER:
            mp = &encoders;
            break;
        default:
            throw ndPluginException(
                t.second, "invalid type"
            );
            break;
        }

        auto pl = mp->find(t.second);

        if (pl == mp->end()) {
            throw ndPluginException(t.second,
                "plugin not found"
            );
        }

        pl->second->GetPlugin()->Create();

        return true;
    }

    return false;
}

bool ndPluginManager::Reap(ndPlugin::ndPluginType type)
{
    size_t count = 0;
    unique_lock<mutex> ul(lock);

    for (auto &t : ndPlugin::types) {
        if (type != ndPlugin::TYPE_BASE && type != t.first)
            continue;

        map_plugin *mp = nullptr;

        switch (t.first) {
        case ndPlugin::TYPE_SINK:
            mp = &sinks;
            break;
        case ndPlugin::TYPE_ENCODER:
            mp = &encoders;
            break;
        default:
            throw ndPluginException(
                t.second, "invalid type"
            );
            break;
        }

        for (map_plugin::iterator p = mp->begin();
            p != mp->end(); ) {

            if (! p->second->GetPlugin()->HasTerminated()) {
                p++;
                continue;
            }

            nd_printf("Plugin exited abnormally: %s: %s\n",
                p->second->GetPlugin()->GetTag().c_str(),
                p->second->GetObjectName().c_str()
            );

            delete p->second->GetPlugin();
            delete p->second;

            count++;
            p = mp->erase(p);
        }
    }

    return (count > 0);
}

void ndPluginManager::BroadcastEvent(ndPlugin::ndPluginType type,
    ndPlugin::ndPluginEvent event, void *param)
{
    unique_lock<mutex> ul(lock);

    for (auto &t : ndPlugin::types) {
        if (type != ndPlugin::TYPE_BASE || type != t.first)
            continue;

        map_plugin *mp = nullptr;

        switch (t.first) {
        case ndPlugin::TYPE_SINK:
            mp = &sinks;
            break;
        case ndPlugin::TYPE_ENCODER:
            mp = &encoders;
            break;
        default:
            throw ndPluginException(
                t.second, "invalid type"
            );
            break;
        }

        for (auto &p : *mp)
            p.second->GetPlugin()->DispatchEvent(event, param);
    }
}

void ndPluginManager::BroadcastSinkPayload(
    const string &channel, size_t length, uint8_t *payload)
{
    unique_lock<mutex> ul(lock);

    for (auto &p : sinks) {
        uint8_t *pd = new uint8_t[length];
        if (pd == nullptr) {
            throw ndSystemException(__PRETTY_FUNCTION__,
                "new sink payload", ENOMEM
            );
        }

        memcpy(pd, payload, length);

        reinterpret_cast<ndPluginSink *>(
            p.second->GetPlugin()
        )->DispatchSinkEvent(channel, length, pd);
    }
}

bool ndPluginManager::DispatchSinkPayload(const string &tag,
    const string &channel, size_t length, uint8_t *payload)
{
    unique_lock<mutex> ul(lock);

    auto p = sinks.find(tag);

    if (p == sinks.end()) return false;

    reinterpret_cast<ndPluginSink *>(
        (*p).second->GetPlugin()
    )->DispatchSinkEvent(channel, length, payload);

    return true;
}

void ndPluginManager::BroadcastEncoderEvent(
    ndPluginEncoder::ndEncoderEvent event, void *param)
{
    unique_lock<mutex> ul(lock);

    for (auto &p : encoders) {
        reinterpret_cast<ndPluginEncoder *>(
            p.second->GetPlugin()
        )->DispatchEncoderEvent(event, param);
    }
}

void ndPluginManager::DumpVersions(ndPlugin::ndPluginType type)
{
    unique_lock<mutex> ul(lock);

    for (auto &t : ndPlugin::types) {
        if (type != ndPlugin::TYPE_BASE || type != t.first)
            continue;

        map_plugin *mp = nullptr;

        switch (t.first) {
        case ndPlugin::TYPE_SINK:
            mp = &sinks;
            break;
        case ndPlugin::TYPE_ENCODER:
            mp = &encoders;
            break;
        default:
            throw ndPluginException(
                t.second, "invalid type"
            );
            break;
        }

        for (auto &p : *mp) {
            string version;
            p.second->GetPlugin()->GetVersion(version);

            fprintf(stderr, "%16s: %s: v%s\n",
                p.second->GetPlugin()->GetTag().c_str(),
                p.second->GetObjectName().c_str(),
                (version.empty()) ? "?.?.?" : version.c_str()
            );
        }
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
