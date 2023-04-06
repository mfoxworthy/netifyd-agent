// Netify Agent
// Copyright (C) 2015-2023 eGloo Incorporated <http://www.egloo.ca>
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

#ifndef _ND_INSTANCE_H
#define _ND_INSTANCE_H

class ndInstanceStatus : public ndSerializer
{
public:
    ndInstanceStatus();

    long cpus;
    struct timespec ts_epoch;
    struct timespec ts_now;
    uint32_t flows;
    uint32_t flows_prev;
    double cpu_user;
    double cpu_user_prev;
    double cpu_system;
    double cpu_system_prev;
#if (SIZEOF_LONG == 4)
    uint32_t maxrss_kb;
    uint32_t maxrss_kb_prev;
#elif (SIZEOF_LONG == 8)
    uint64_t maxrss_kb;
    uint64_t maxrss_kb_prev;
#endif
#if (defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H))
    size_t tcm_alloc_kb;
    size_t tcm_alloc_kb_prev;
#endif
    bool dhc_status;
    size_t dhc_size;
    bool sink_uploads;
    bool sink_status;
    size_t sink_queue_size;
    ndJsonResponseCode sink_resp_code;

    template <class T>
    void Encode(T &output) const {
        serialize(output, { "version" }, (double)ND_JSON_VERSION);
        serialize(output, { "timestamp" }, time(NULL));
        serialize(output, { "update_interval" },
            ndGC.update_interval
        );
        serialize(output, { "update_imf" }, ndGC.update_imf);
        serialize(output, { "uptime" }, unsigned(
            ts_now.tv_sec - ts_epoch.tv_sec
        ));
        serialize(output, { "cpu_cores" }, (unsigned)cpus);
        serialize(output, { "cpu_user" }, cpu_user);
        serialize(output, { "cpu_user_prev" }, cpu_user_prev);
        serialize(output, { "cpu_system" }, cpu_system);
        serialize(output, { "cpu_system_prev" }, cpu_system_prev);
        serialize(output, { "flow_count" }, flows);
        serialize(output, { "flow_count_prev" }, flows_prev);
        serialize(output, { "maxrss_kb" }, maxrss_kb);
        serialize(output, { "maxrss_kb_prev" }, maxrss_kb_prev);
#if (defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H))
        serialize(output, { "tcm_kb" },(unsigned)tcm_alloc_kb);
        serialize(output, { "tcm_kb_prev" },
            (unsigned)tcm_alloc_kb_prev
        );
#endif // _ND_USE_LIBTCMALLOC
        serialize(output, { "dhc_status" }, dhc_status);
        if (dhc_status)
            serialize(output, { "dhc_size" }, dhc_size);

        serialize(output, { "sink_status" }, sink_status);
        serialize(output, { "sink_uploads" },
            (ndGC_UPLOAD_ENABLED) ? true : false
        );

        if (sink_status) {
            serialize(output, { "sink_queue_size_kb" },
                sink_queue_size / 1024
            );
            serialize(output, { "sink_queue_max_size_kb" },
                ndGC.max_backlog / 1024
            );
            serialize(output, { "sink_resp_code" },
                (unsigned)sink_resp_code
            );
        }
    }
};

class ndInstance;
class ndInstanceThread : public ndThread
{
public:
    ndInstanceThread(const string &tag, ndInstance *instance)
        : ndThread(tag), instance(instance) { }
    virtual ~ndInstanceThread() { Join(); }

    virtual void *Entry(void);

protected:
    friend class ndInstance;

    ndInstance *instance;
};

class ndInstance
{
public:
    static ndInstance& Create(const sigset_t &sigset,
        const string &tag = "", bool threaded = false);

    static void Destroy(void);

    ndInstance() = delete;
    ndInstance(const ndInstance&) = delete;
    ndInstance& operator=(const ndInstance&) = delete;

    static inline ndInstance& GetInstance() {
        return *instance;
    }

    static void InitializeSignals(
        sigset_t &sigset, bool minimal = false);

    enum ndConfigResult {
        ndCR_OK,
        ndCR_AGENT_STATUS,
        ndCR_DISABLED_OPTION,
        ndCR_DUMP_LIST,
        ndCR_EXPORT_APPS,
        ndCR_FORCE_RESULT,
        ndCR_GENERATE_UUID,
        ndCR_HASH_TEST,
        ndCR_INVALID_INTERFACES,
        ndCR_INVALID_OPTION,
        ndCR_INVALID_VALUE,
        ndCR_LIBCURL_FAILURE,
        ndCR_LOAD_FAILURE,
        ndCR_LOOKUP_ADDR,
        ndCR_PROVISION_UUID,
        ndCR_SETOPT_SINK_DISABLE,
        ndCR_SETOPT_SINK_ENABLE,
        ndCR_USAGE_OR_VERSION,
    };

#define ndCR_Pack(r, c) ((c << 16) + (r & 0x0000ffff))
#define ndCR_Code(c) ((c & 0xffff0000) >> 16)
#define ndCR_Result(r) (r & 0x0000ffff)

    uint32_t InitializeConfig(int argc, char * const argv[]);

    bool Daemonize(void);

    enum ndDumpFlags {
        ndDUMP_NONE = 0x00,
        ndDUMP_TYPE_PROTOS = 0x01,
        ndDUMP_TYPE_APPS = 0x02,
        ndDUMP_TYPE_CAT_APP = 0x04,
        ndDUMP_TYPE_CAT_PROTO = 0x08,
        ndDUMP_TYPE_RISKS = 0x10,
        ndDUMP_TYPE_VALID = 0x20,
        ndDUMP_SORT_BY_TAG = 0x40,
        ndDUMP_TYPE_CATS = (
            ndDUMP_TYPE_CAT_APP | ndDUMP_TYPE_CAT_PROTO
        ),
        ndDUMP_TYPE_ALL = (
            ndDUMP_TYPE_PROTOS | ndDUMP_TYPE_APPS
        )
    };

    bool DumpList(uint8_t type = ndDUMP_TYPE_ALL);

    bool LookupAddress(const string &ip);

    void CommandLineHelp(bool version_only = false);

    bool CheckAgentUUID(void);

    bool AgentStatus(void);

    void ProcessUpdate(void);

    int Run(void);

    inline void Terminate(void) {
        if (terminate.load())
            terminate_force = true;
        else
            terminate = true;
        if (threaded && thread != nullptr) thread->Terminate();
    }

    inline bool Terminated(void) {
        if (threaded && thread != nullptr)
            return thread->HasTerminated();
        return terminate.load();
    }

    inline const string& GetVersion() const { return version; }
    inline const ndInstanceStatus& GetStatus() const { return status; }

    template <class T>
    void EncodeApplications(T &output) {
        nd_apps_t entries;
        apps.Get(entries);
        for (auto &app : entries) {
            T jo;

            jo["id"] = app.second;
            jo["tag"] = app.first;

            output.push_back(jo);
        }
    };
    template <class T>
    void EncodeProtocols(T &output) const {
        for (auto &proto : nd_protos) {
            T jo;

            jo["id"] = proto.first;
            jo["tag"] = proto.second;

            output.push_back(jo);
        }
    };

    int exit_code;

    ndApplications apps;
    ndCategories categories;
    ndDomains domains;
    ndInterfaces interfaces;
    ndAddrType addr_types;
    ndDNSHintCache *dns_hint_cache;
    ndFlowHashCache *flow_hash_cache;
    ndFlowMap *flow_buckets;
#ifdef _ND_USE_NETLINK
    ndNetlink *netlink;
#endif

    ndSinkThread *thread_sink;
    ndSocketThread *thread_socket;
    ndNetifyApiThread *thread_napi;
#ifdef _ND_USE_CONNTRACK
    ndConntrackThread *thread_conntrack;
#endif
    nd_detection_threads thread_detection;

protected:
    friend class ndInstanceThread;

    static ndInstance *instance;

    void *Entry(void);

    bool Reload(void);

    bool CreateCaptureThreads(nd_capture_threads &threads);
    void DestroyCaptureThreads(nd_capture_threads &threads);

    sigset_t sigset;

    string tag;
    string self;
    pid_t self_pid;
    string version;

    atomic_bool terminate;
    atomic_bool terminate_force;

    bool threaded;
    ndInstanceThread *thread;

    string conf_filename;

    atomic<uint64_t> flows;

    ndInstanceStatus status;

private:
    ndInstance(const sigset_t &sigset,
        const string &tag = "", bool threaded = false);
    virtual ~ndInstance();
};

#endif // _ND_INSTANCE_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
