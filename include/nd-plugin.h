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
    ndPlugin *ndPluginInit( \
        const string &tag, const map<string, string> &params) { \
        class_name *p = new class_name(tag, params); \
        if (p == nullptr) return nullptr; \
        if (p->GetType() != ndPlugin::TYPE_PROC && \
            p->GetType() != ndPlugin::TYPE_SINK) { \
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

class ndPlugin : public ndThread, public ndSerializer
{
public:
    enum Type
    {
        TYPE_BASE,
        TYPE_PROC,
        TYPE_SINK,
    };

    ndPlugin(
        Type type,
        const string &tag, const map<string, string> &params);
    virtual ~ndPlugin();

    virtual void *Entry(void) = 0;

    virtual void GetVersion(string &version) = 0;

    template <class T>
    void GetStatus(T &output) const {
        switch (type) {
        case TYPE_PROC:
            serialize(output, { tag, "type" }, "processor");
            break;
        case TYPE_SINK:
            serialize(output, { tag, "type" }, "sink");
            break;
        default:
            serialize(output, { tag, "type" }, "unkown");
            break;
        }
    }

    enum Event
    {
        EVENT_RELOAD,
        EVENT_STATUS_UPDATE,
    };

    virtual void DispatchEvent(
        Event event, void *param = nullptr) { };

    static const map<ndPlugin::Type, string> types;

    Type GetType(void) { return type; };

protected:
    Type type;
    string conf_filename;
    vector<string> sink_targets;
    string sink_channel;
};

class ndPluginProcessor : public ndPlugin
{
public:
    ndPluginProcessor(
        const string &tag, const map<string, string> &params);
    virtual ~ndPluginProcessor();

    enum Event {
        EVENT_INIT,
        EVENT_INTERFACES,
        EVENT_PKT_GLOBAL_STATS,
        EVENT_PKT_CAPTURE_STATS,
        EVENT_FLOW_NEW,
        EVENT_FLOW_MAP,
        EVENT_FLOW_UPDATED,
        EVENT_FLOW_EXPIRING,
        EVENT_FLOW_EXPIRED,
        EVENT_COMPLETE,
    };

    template <class T>
    void GetStatus(T &output) const {
        ndPlugin::GetStatus(output);
    }

    virtual void DispatchProcessorEvent(
        Event event, void *param = nullptr) = 0;

protected:
};

class ndPluginSink : public ndPlugin
{
public:
    ndPluginSink(
        const string &tag, const map<string, string> &params);
    virtual ~ndPluginSink();

    template <class T>
    void GetStatus(T &output) const {
        ndPlugin::GetStatus(output);
    }

    virtual void DispatchSinkEvent(
        const string &channel,
        size_t length, const uint8_t *payload) = 0;

protected:
};

#ifdef _ND_INTERNAL

class ndPluginLoader
{
public:
    ndPluginLoader(
        const string &tag,
        const string &so_name, const map<string, string> &params);
    virtual ~ndPluginLoader();

    inline ndPlugin *GetPlugin(void) { return plugin; };
    inline const string& GetTag(void) { return tag; };
    inline const string& GetObjectName(void) { return so_name; };

protected:
    string tag;
    string so_name;
    void *so_handle;
    ndPlugin *plugin;
};

class ndPluginManager : public ndSerializer
{
public:
    virtual ~ndPluginManager();

    void Load(
        ndPlugin::Type type = ndPlugin::TYPE_BASE,
        bool create = true);

    bool Create(ndPlugin::Type type = ndPlugin::TYPE_BASE);

    bool Reap(ndPlugin::Type type = ndPlugin::TYPE_BASE);

    void BroadcastEvent(ndPlugin::Type type,
        ndPlugin::Event event, void *param = nullptr);

    void BroadcastSinkPayload(
        const string &channel, size_t length, uint8_t *payload);
    bool DispatchSinkPayload(const string &tag,
        const string &channel, size_t length, uint8_t *payload);

    void BroadcastProcessorEvent(
        ndPluginProcessor::Event event, void *param = nullptr);

    template <class T>
    void Encode(T &output) const {
        T plugins;

        for (auto &p : processors)
            p.second->GetPlugin()->GetStatus(plugins);
        for (auto &p : sinks)
            p.second->GetPlugin()->GetStatus(plugins);

        serialize(output, { "plugins" }, plugins);
    }

    void DumpVersions(
        ndPlugin::Type type = ndPlugin::TYPE_BASE);

protected:
    mutex lock;

    typedef map<string, ndPluginLoader *> map_plugin;

    map_plugin processors;
    map_plugin sinks;
};

#endif // _ND_INTERNAL
#endif // _ND_PLUGIN_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
