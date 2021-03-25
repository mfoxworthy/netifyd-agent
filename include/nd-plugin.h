// Netify Agent
// Copyright (C) 2015-2020 eGloo Incorporated <http://www.egloo.ca>
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

#define _ND_PLUGIN_VER  0x20180813

#define ndStartDetectionThreads() kill(getpid(), SIGUSR1)
#define ndStopDetectionThreads()  kill(getpid(), SIGUSR2)

#define ndPluginInit(class_name) \
    extern "C" { \
    ndPlugin *ndPluginInit(const string &tag) { \
        class_name *p = new class_name(tag); \
        if (p == NULL) return NULL; \
        if (p->GetType() != ndPlugin::TYPE_SINK_TASK && \
            p->GetType() != ndPlugin::TYPE_SINK_SERVICE && \
            p->GetType() != ndPlugin::TYPE_DETECTION) { \
                nd_printf("Invalid plugin type detected during init: %s\n", \
                    tag.c_str()); \
                delete p; \
                return NULL; \
        } \
        return dynamic_cast<ndPlugin *>(p); \
    } }

class ndPluginException : public ndException
{
public:
    explicit ndPluginException(
        const string &where_arg, const string &what_arg) throw()
        : ndException(where_arg, what_arg) { }
};

typedef map<string, string> ndPluginFiles;

typedef map<string, ndJsonPluginParams> ndPluginParams;
typedef map<string, ndJsonPluginReplies> ndPluginReplies;

class ndPlugin : public ndThread
{
public:
    ndPlugin(const string &tag);
    virtual ~ndPlugin();

    virtual void *Entry(void) = 0;

    enum ndPluginType
    {
        TYPE_BASE,
        TYPE_SINK_SERVICE,
        TYPE_SINK_TASK,
        TYPE_DETECTION,
    };

    ndPluginType GetType(void) { return type; };

protected:
    ndPluginType type;
};

class ndPluginSink : public ndPlugin
{
public:
    ndPluginSink(const string &tag);
    virtual ~ndPluginSink();

    virtual void SetParams(const string uuid_dispatch, const ndJsonPluginParams &params);

    virtual void GetReplies(
        ndPluginFiles &files, ndPluginFiles &data, ndPluginReplies &replies);

protected:
    virtual bool PopParams(string &uuid_dispatch, ndJsonPluginParams &params);

    virtual void PushFile(const string &tag, const string &filename);
    virtual void PushData(const string &tag, const string &data);

    virtual void PushReply(
        const string &uuid_dispatch, const string &key, const string &value);
    inline void PushReplyLock(
        const string &uuid_dispatch, const string &key, const string &value)
    {
        Lock();
        PushReply(uuid_dispatch, key, value);
        Unlock();
    }

    ndPluginFiles files;
    ndPluginFiles data;
    ndPluginParams params;
    ndPluginReplies replies;
};

class ndPluginDetection : public ndPlugin
{
public:
    ndPluginDetection(const string &tag);
    virtual ~ndPluginDetection();

    virtual void ProcessFlow(const ndFlow *flow) const = 0;

protected:
};

class ndPluginService : public ndPluginSink
{
public:
    ndPluginService(const string &tag);
    virtual ~ndPluginService();
};

class ndPluginTask : public ndPluginSink
{
public:
    ndPluginTask(const string &tag);
    virtual ~ndPluginTask();

    virtual void SetParams(const string uuid_dispatch, const ndJsonPluginParams &params);

protected:
    virtual bool PopParams(ndJsonPluginParams &params);

    virtual void PushReply(const string &key, const string &value);
    inline void PushReplyLock(const string &key, const string &value)
    {
        Lock();
        PushReply(key, value);
        Unlock();
    }

    string uuid_dispatch;
};

#ifdef _ND_INTERNAL

class ndPluginLoader
{
public:
    ndPluginLoader(const string &so_name, const string &tag);
    virtual ~ndPluginLoader();

    inline ndPlugin *GetPlugin(void) { return plugin; };

protected:
    string so_name;
    void *so_handle;
    ndPlugin *plugin;
};

#endif // _ND_INTERNAL

#endif // _ND_PLUGIN_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
