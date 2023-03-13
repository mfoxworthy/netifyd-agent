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
    ndInstance(const sigset_t &sigset,
        const string &tag = "", bool threaded = false);
    virtual ~ndInstance();

    static void InitializeSignals(
        sigset_t &sigset, bool minimal = false);

    bool LoadConfig(const string &filename = "");
    bool ParseArguments(int argc, char *argv[]);

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

    int Create(void);

    int exit_code;

protected:
    friend class ndInstanceThread;

    void *Entry(void);

    sigset_t sigset;

    string tag;

    atomic_bool terminate;
    atomic_bool terminate_force;

    bool threaded;
    ndInstanceThread *thread;

    string conf_filename;
    ndGlobalConfig config;
};

#endif // _ND_INSTANCE_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
