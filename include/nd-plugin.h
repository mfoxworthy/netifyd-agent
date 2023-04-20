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

#ifndef _ND_PLUGIN_H
#define _ND_PLUGIN_H

#define _ND_PLUGIN_VER  0x20230309

#define ndPluginInit(class_name) \
extern "C" { \
    ndPlugin *ndPluginInit(const string &tag) { \
        class_name *p = new class_name(tag); \
        if (p == nullptr) return nullptr; \
        if (p->GetType() != ndPlugin::TYPE_STATS && \
            p->GetType() != ndPlugin::TYPE_DETECTION) { \
                nd_printf("Invalid plugin type detected during init: %s [%u]\n", \
                    tag.c_str(), p->GetType()); \
                delete p; \
                return nullptr; \
        } \
        return dynamic_cast<ndPlugin *>(p); \
    } \
}

class ndPluginException : public ndException
{
public:
    explicit ndPluginException(
        const string &where_arg, const string &what_arg) throw()
        : ndException(where_arg, what_arg) { }
};

class ndPlugin : public ndThread
{
public:
    enum ndPluginType
    {
        TYPE_BASE,
        TYPE_STATS,
        TYPE_DETECTION,
    };

    ndPlugin(ndPluginType type, const string &tag);
    virtual ~ndPlugin();

    virtual void *Entry(void) = 0;

    virtual void GetVersion(string &version) = 0;

    enum ndPluginEvent
    {
        EVENT_RELOAD,
        EVENT_STATUS_UPDATE,
    };

    virtual void ProcessEvent(
        ndPluginEvent event, void *param = nullptr) { };

    static const map<ndPlugin::ndPluginType, string> types;
    ndPluginType GetType(void) { return type; };

protected:
    ndPluginType type;
};

class ndPluginStats : public ndPlugin
{
public:
    ndPluginStats(const string &tag);
    virtual ~ndPluginStats();

    enum ndStatsEvent {
        EVENT_INIT,
        EVENT_INTERFACES,
        EVENT_PKT_CAPTURE_STATS,
        EVENT_PKT_GLOBAL_STATS,
        EVENT_FLOW_MAP,
        EVENT_COMPLETE,
    };

    virtual void ProcessStatsEvent(
        ndStatsEvent event, void *param = nullptr) = 0;

protected:
};

class ndPluginDetection : public ndPlugin
{
public:

    enum ndDetectionEvent
    {
        EVENT_NEW,
        EVENT_UPDATED,
        EVENT_EXPIRING,
    };

    ndPluginDetection(const string &tag);
    virtual ~ndPluginDetection();

    virtual void ProcessDetectionEvent(
        ndDetectionEvent event, ndFlow *flow) = 0;

protected:
};

#ifdef _ND_INTERNAL

class ndPluginLoader
{
public:
    ndPluginLoader(const string &so_name, const string &tag);
    virtual ~ndPluginLoader();

    inline ndPlugin *GetPlugin(void) { return plugin; };
    inline const string& GetObjectName(void) { return so_name; };

protected:
    string so_name;
    void *so_handle;
    ndPlugin *plugin;
};

class ndPluginManager : public ndSerializer
{
public:
    virtual ~ndPluginManager();

    void Load(
        ndPlugin::ndPluginType type = ndPlugin::TYPE_BASE,
        bool create = true);

    bool Create(ndPlugin::ndPluginType type = ndPlugin::TYPE_BASE);

    bool Reap(ndPlugin::ndPluginType type = ndPlugin::TYPE_BASE);

    void BroadcastEvent(ndPlugin::ndPluginType type,
        ndPlugin::ndPluginEvent event, void *param = nullptr);

    void BroadcastStatsEvent(
        ndPluginStats::ndStatsEvent event, void *param = nullptr);

    void BroadcastDetectionEvent(
        ndPluginDetection::ndDetectionEvent event, ndFlow *flow);

    template <class T>
    void Encode(T &output) const {
        serialize(output, { "plugins", "timestamp" }, time(NULL));
    }

    void DumpVersions(
        ndPlugin::ndPluginType type = ndPlugin::TYPE_BASE);

protected:
    map<ndPlugin::ndPluginType, vector<ndPluginLoader *>> plugins;
};
#endif // _ND_INTERNAL
#endif // _ND_PLUGIN_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
