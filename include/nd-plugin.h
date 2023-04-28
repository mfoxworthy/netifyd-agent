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
        const string &tag, const ndPlugin::Params &params) { \
        class_name *p = new class_name(tag, params); \
        if (p == nullptr) return nullptr; \
        if (p->GetType() != ndPlugin::TYPE_PROC && \
            p->GetType() != ndPlugin::TYPE_SINK) { \
                nd_printf("Invalid plugin type: %s [%u]\n", \
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

    typedef map<string, string> Params;
    typedef set<string> Channels;

    ndPlugin(
        Type type,
        const string &tag, const Params &params);
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
};

class ndPluginSinkPayload
{
public:
    inline static ndPluginSinkPayload *Create(
        size_t length, const uint8_t *data,
        const ndPlugin::Channels &channels) {

        ndPluginSinkPayload *p = new ndPluginSinkPayload(
            length, data, channels
        );

        if (p == nullptr) {
            throw ndSystemException(__PRETTY_FUNCTION__,
                "new sink payload", ENOMEM
            );
        }

        return p;
    }

    inline static ndPluginSinkPayload *Create(
        const ndPluginSinkPayload &payload) {
        return Create(
            payload.length, payload.data, payload.channels
        );
    }

    inline static ndPluginSinkPayload *Create(
        const ndPluginSinkPayload *payload) {
        return Create(
            payload->length, payload->data, payload->channels
        );
    }

    inline static ndPluginSinkPayload *Create(const json &j,
        const ndPlugin::Channels &channels) {
        string output;
        nd_json_to_string(j, output, ndGC_DEBUG);

        return Create(output.size(),
            (const uint8_t *)output.c_str(), channels);
    }

    ndPluginSinkPayload() : length(0), data(nullptr) { }

    ndPluginSinkPayload(size_t length, const uint8_t *data,
        const ndPlugin::Channels &channels)
        : length(length), data(nullptr), channels(channels) {

        this->data = new uint8_t[length];

        if (this->data == nullptr) {
            throw ndSystemException(
                __PRETTY_FUNCTION__,
                "new sink payload data", ENOMEM
            );
        }

        memcpy(this->data, data, length);
    }

    virtual ~ndPluginSinkPayload() {
        if (data) {
            delete [] data;
            data = nullptr;
        }
        length = 0;
    }

    size_t length;
    uint8_t *data;
    ndPlugin::Channels channels;
};

class ndPluginProcessor : public ndPlugin
{
public:
    ndPluginProcessor(
        const string &tag, const ndPlugin::Params &params);
    virtual ~ndPluginProcessor();

    enum Event {
        EVENT_FLOW_MAP, // ndFlowMap *
        EVENT_FLOW_NEW, // nd_flow_ptr
        EVENT_FLOW_UPDATED, // nd_flow_ptr
        EVENT_FLOW_EXPIRING, // nd_flow_ptr
        EVENT_FLOW_EXPIRED, // nd_flow_ptr
        EVENT_INTERFACES, // ndInterfaces
        EVENT_PKT_CAPTURE_STATS, // string, ndPacketStats *
        EVENT_PKT_GLOBAL_STATS, // ndPacketStats *
        EVENT_UPDATE_INIT, // ndInstanceStatus *
        EVENT_UPDATE_COMPLETE,
    };

    template <class T>
    void GetStatus(T &output) const {
        ndPlugin::GetStatus(output);
    }

    virtual void DispatchProcessorEvent(Event event,
        ndFlowMap *flow_map) { }
    virtual void DispatchProcessorEvent(Event event,
        nd_flow_ptr& flow) { }
    virtual void DispatchProcessorEvent(Event event,
        ndInterfaces *interfaces) { }
    virtual void DispatchProcessorEvent(Event event,
        const string &iface, ndPacketStats *stats) { }
    virtual void DispatchProcessorEvent(Event event,
        ndPacketStats *stats) { }
    virtual void DispatchProcessorEvent(Event event,
        ndInstanceStatus *status) { }
    virtual void DispatchProcessorEvent(Event event) { }

protected:
    virtual void DispatchSinkPayload(
        const string &target, const ndPlugin::Channels &channels,
        size_t length, const uint8_t *payload);

    inline void DispatchSinkPayload(
        const string &target, const ndPlugin::Channels &channels,
        const vector<uint8_t> &payload) {
        DispatchSinkPayload(
            target, channels, payload.size(), &payload[0]
        );
    }

    enum DispatchFlags {
        DF_NONE,
        DF_ADD_HEADER = 0x01,
        DF_FORMAT_MSGPACK = 0x02,
    };

    virtual void DispatchSinkPayload(
        const string &target, const ndPlugin::Channels &channels,
        const json &j, uint8_t flags = DF_NONE);
};

#define _ND_PLQ_DEFAULT_MAX_SIZE    2097152

class ndPluginSink : public ndPlugin
{
public:
    ndPluginSink(
        const string &tag, const ndPlugin::Params &params);
    virtual ~ndPluginSink();

    template <class T>
    void GetStatus(T &output) const {
        ndPlugin::GetStatus(output);
    }

    virtual void QueuePayload(ndPluginSinkPayload *payload);

protected:
    size_t plq_size;
    size_t plq_size_max;
    queue<ndPluginSinkPayload *> plq_public;
    queue<ndPluginSinkPayload *> plq_private;
    pthread_cond_t plq_cond;
    pthread_mutex_t plq_cond_mutex;

    size_t PullPayloadQueue(void);
    size_t WaitOnPayloadQueue(unsigned timeout = 1);

    inline ndPluginSinkPayload *PopPayloadQueue(void) {
        if (! plq_private.size()) return nullptr;
        ndPluginSinkPayload *p = plq_private.front();
        plq_private.pop();
        plq_size -= p->length;
        return p;
    }
};

class ndPluginLoader
{
public:
    ndPluginLoader(
        const string &tag,
        const string &so_name, const ndPlugin::Params &params);
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

    void BroadcastSinkPayload(ndPluginSinkPayload *payload);
    bool DispatchSinkPayload(
        const string &target, ndPluginSinkPayload *payload);

    void BroadcastProcessorEvent(ndPluginProcessor::Event event,
        ndFlowMap *flow_map);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event,
        nd_flow_ptr& flow);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event,
        ndInterfaces *interfaces);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event,
        const string &iface, ndPacketStats *stats);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event,
        ndPacketStats *stats);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event,
        ndInstanceStatus *status);
    void BroadcastProcessorEvent(ndPluginProcessor::Event event);

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

#endif // _ND_PLUGIN_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
