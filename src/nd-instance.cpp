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

#include <iomanip>
#include <iostream>
#include <set>
#include <map>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <vector>
#include <locale>
#include <atomic>
#include <regex>
#include <mutex>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <locale.h>
#include <syslog.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <netdb.h>
#include <netinet/in.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <curl/curl.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <resolv.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

#if defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
#include <gperftools/malloc_extension.h>
#elif defined(_ND_USE_LIBJEMALLOC) && defined(HAVE_JEMALLOC_JEMALLOC_H)
#include <jemalloc/jemalloc.h>
#elif defined(HAVE_MALLOC_TRIM)
#include <malloc.h>
#endif

#include <radix/radix_tree.hpp>

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-ndpi.h"
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
#include "nd-flow-parser.h"
#include "nd-thread.h"
#ifdef _ND_USE_CONNTRACK
#include "nd-conntrack.h"
#endif
#include "nd-dhc.h"
#include "nd-fhc.h"
#include "nd-detection.h"
#include "nd-capture.h"
#ifdef _ND_USE_LIBPCAP
#include "nd-capture-pcap.h"
#endif
#ifdef _ND_USE_TPACKETV3
#include "nd-capture-tpv3.h"
#endif
#include "nd-socket.h"
#include "nd-sink.h"
#include "nd-base64.h"
#ifdef _ND_USE_PLUGINS
#include "nd-plugin.h"
#endif
#include "nd-signal.h"
#include "nd-napi.h"
#include "nd-instance.h"

void *ndInstanceThread::Entry(void)
{
    if (! ShouldTerminate()) return instance->Entry();
    return nullptr;
}

ndInstance::ndInstance(
    const sigset_t &sigset, const string &tag, bool threaded)
    : exit_code(EXIT_SUCCESS), sigset(sigset),
    tag(tag.empty() ? PACKAGE_TARNAME : tag),
    threaded(threaded), thread(nullptr),
    conf_filename(ND_CONF_FILE_NAME)
{
    terminate = false;
    terminate_force = false;

    if (threaded)
        thread = new ndInstanceThread(tag, this);
// TODO:
//        if (thread == nullptr)
//            throw...
}

ndInstance::~ndInstance()
{
    if (threaded && thread != nullptr) {
        thread->Terminate();
        delete thread;
    }
}

void ndInstance::InitializeSignals(sigset_t &sigset, bool minimal)
{
    if (! minimal) {
        sigfillset(&sigset);
        //sigdelset(&sigset, SIGPROF);
        //sigdelset(&sigset, SIGINT);
        sigdelset(&sigset, SIGQUIT);
        sigprocmask(SIG_BLOCK, &sigset, NULL);
    }

    sigemptyset(&sigset);
    sigaddset(&sigset, ND_SIG_SINK_REPLY);
    sigaddset(&sigset, ND_SIG_UPDATE);
    sigaddset(&sigset, ND_SIG_CONNECT);
    sigaddset(&sigset, ND_SIG_NAPI_UPDATE);
    sigaddset(&sigset, ND_SIG_NAPI_UPDATED);
    sigaddset(&sigset, SIGIO);

    if (! minimal) {
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGINT);
#ifdef SIGPWR
        sigaddset(&sigset, SIGPWR);
#endif
        sigaddset(&sigset, SIGTERM);
        sigaddset(&sigset, SIGUSR1);
        sigaddset(&sigset, SIGUSR2);
    }
}

bool ndInstance::LoadConfig(const string &filename)
{
    if (! filename.empty()) conf_filename = filename;
    return (config.Load(conf_filename) < 0) ? false : true;
}

bool ndInstance::ParseArguments(int argc, char *argv[])
{
    return false;
}

int ndInstance::Create(void)
{
    if (threaded) {
        if (thread == nullptr) {
            exit_code = EXIT_FAILURE;
            return exit_code;
        }

        try {
            thread->Create();
        }
        catch (ndThreadException &e) {
            exit_code = EXIT_FAILURE;
        }

        return exit_code;
    }

    void *rc __attribute__((unused)) = Entry();

    return exit_code;
}

void *ndInstance::ndInstance::Entry(void)
{
    int c = 0;
    struct timespec tspec_sigwait = { 1, 0 };

    do {
        int sig;
        siginfo_t si;

        nd_dprintf("%s: tick: %d\n", tag.c_str(), ++c);

        if ((sig = sigtimedwait(&sigset, &si, &tspec_sigwait)) < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            exit_code = -1;
            terminate = true;
            nd_printf("sigwaitinfo: %s\n", strerror(errno));
            continue;
        }

        if (sig == SIGINT || sig == SIGTERM) {
            terminate = true;
        }
    }
    while (! terminate.load());

    return nullptr;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
