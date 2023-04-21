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

class ndPluginProcessor : public ndPlugin
{
public:
    ndPluginProcessor(
        const string &tag, const ndPlugin::Params &params);
    virtual ~ndPluginProcessor();

    enum Event {
        EVENT_FLOW_MAP,
        EVENT_FLOW_NEW,
        EVENT_FLOW_UPDATED,
        EVENT_FLOW_EXPIRING,
        EVENT_FLOW_EXPIRED,
        EVENT_INTERFACES,
        EVENT_PKT_CAPTURE_STATS,
        EVENT_PKT_GLOBAL_STATS,
        EVENT_UPDATE_INIT,
        EVENT_UPDATE_COMPLETE,
    };

    template <class T>
    void GetStatus(T &output) const {
        ndPlugin::GetStatus(output);
    }

    virtual void DispatchProcessorEvent(
        Event event, void *param = nullptr) = 0;

protected:
    virtual bool DispatchSinkPayload(
        size_t length, const uint8_t *payload);

    map<string, set<string>> sink_targets;
};

class ndPluginSinkPayload
{
public:
    ndPluginSinkPayload() : length(0), data(nullptr) { }
    ndPluginSinkPayload(
        size_t length, const uint8_t *data, const set<string> &channels)
        : length(length), data(nullptr), channels(channels) {
        this->data = new uint8_t[length];
        if (this->data == nullptr) {
            throw ndSystemException(__PRETTY_FUNCTION__,
                "new sink payload", ENOMEM
            );
        }
        memcpy(this->data, data, length);
    }
    ndPluginSinkPayload(const ndPluginSinkPayload &payload)
        : length(payload.length), data(nullptr),
        channels(payload.channels) {
        data = new uint8_t[length];
        if (data == nullptr) {
            throw ndSystemException(__PRETTY_FUNCTION__,
                "new sink payload", ENOMEM
            );
        }
        memcpy(data, payload.data, length);
    }
    ndPluginSinkPayload(const ndPluginSinkPayload *payload)
        : length(payload->length), data(nullptr),
        channels(payload->channels) {
        data = new uint8_t[length];
        if (data == nullptr) {
            throw ndSystemException(__PRETTY_FUNCTION__,
                "new sink payload", ENOMEM
            );
        }
        memcpy(data, payload->data, length);
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
    set<string> channels;
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

#ifdef _ND_INTERNAL

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
