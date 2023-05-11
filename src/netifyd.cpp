// Netify Agent 🥷
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
#elif defined(HAVE_MALLOC_TRIM)
#include <malloc.h>
#endif

#include <radix/radix_tree.hpp>

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-signal.h"
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
#include "nd-dhc.h"
#include "nd-fhc.h"
#include "nd-thread.h"
#ifdef _ND_USE_PLUGINS
class ndInstanceStatus;
#include "nd-plugin.h"
#endif
#include "nd-instance.h"
#include "nd-flow-parser.h"
#ifdef _ND_USE_CONNTRACK
#include "nd-conntrack.h"
#endif
#include "nd-detection.h"
#include "nd-capture.h"
#ifdef _ND_USE_LIBPCAP
#include "nd-capture-pcap.h"
#endif
#ifdef _ND_USE_TPACKETV3
#include "nd-capture-tpv3.h"
#endif
#ifdef _ND_USE_NFQUEUE
#include "nd-capture-nfq.h"
#endif
#include "nd-base64.h"
#include "nd-napi.h"

int main(int argc, char *argv[])
{
    int rc = 0;
    uint32_t result;

    setlocale(LC_ALL, "");

    openlog(
        PACKAGE_TARNAME,
        LOG_NDELAY | LOG_PID | LOG_PERROR,
        LOG_DAEMON
    );

    nd_seed_rng();

    sigset_t sigset;
    sigfillset(&sigset);

    //sigdelset(&sigset, SIGPROF);
    //sigdelset(&sigset, SIGINT);
    sigdelset(&sigset, SIGQUIT);

    sigprocmask(SIG_BLOCK, &sigset, NULL);

    sigemptyset(&sigset);
    sigaddset(&sigset, ND_SIG_UPDATE);
    sigaddset(&sigset, ND_SIG_UPDATE_NAPI);
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGIO);
#ifdef SIGPWR
    sigaddset(&sigset, SIGPWR);
#endif
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGUSR1);
    sigaddset(&sigset, SIGUSR2);

    ndInstance& instance = ndInstance::Create();

    result = instance.InitializeConfig(argc, argv);

    if (ndCR_Result(result) != ndInstance::ndCR_OK)
        return ndCR_Code(result);

    if (instance.Daemonize() == false)
        return 1;

    // When using provided timers, ensure they initialized after
    // Daemonize() is called, otherwise on some platforms,
    // timer IDs are not maintained after fork(2).
    if (instance.InitializeTimers() == false)
        return 1;

    rc = instance.Run();

    if (rc == 0) {
        int sig;
        siginfo_t si;
        const struct timespec tspec_sigwait = { 1, 0 };

        while (! instance.HasTerminated()) {

            if ((sig = sigtimedwait(
                &sigset, &si, &tspec_sigwait)) < 0) {

                if (errno == EAGAIN || errno == EINTR) continue;

                nd_printf("sigwaitinfo: %s\n", strerror(errno));

                rc = -1;
                instance.Terminate();
                continue;
            }

            instance.SendSignal(si);
        }
    }

    ndInstance::Destroy();

    return rc;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
