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
        ndCR_DISABLED_OPTION,
        ndCR_INVALID_OPTION,
        ndCR_INVALID_VALUE,
        ndCR_LOAD_FAILURE,
        ndCR_SETOPT_SINK_ENABLE,
        ndCR_SETOPT_SINK_DISABLE,
        ndCR_FORCE_RESULT,
        ndCR_EXPORT_APPS,
        ndCR_DUMP_LIST,
    };

#define ndCR_Pack(r, c) ((c << 16) + (r & 0x0000ffff))
#define ndCR_Code(c) ((c & 0xffff0000) >> 16)
#define ndCR_Result(r) (r & 0x0000ffff)

    uint32_t InitializeConfig(
        int argc, char * const argv[], const string &filename = "");

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

    int exit_code;

    ndApplications apps;
    ndCategories categories;
    ndDomains domains;

protected:
    friend class ndInstanceThread;

    static ndInstance *instance;

    void *Entry(void);

    bool Reload(void);

    sigset_t sigset;

    string tag;
    string self;

    atomic_bool terminate;
    atomic_bool terminate_force;

    bool threaded;
    ndInstanceThread *thread;

    string conf_filename;

    atomic<uint64_t> flows;

    nd_agent_stats agent_stats;

private:
    ndInstance(const sigset_t &sigset,
        const string &tag = "", bool threaded = false);
    virtual ~ndInstance();
};

#endif // _ND_INSTANCE_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
