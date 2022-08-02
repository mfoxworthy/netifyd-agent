// Netify Agent Test Suite
// Copyright (C) 2022 eGloo Incorporated <http://www.egloo.ca>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdexcept>
#include <vector>
#include <set>
#include <map>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <fstream>
#include <sstream>
#include <atomic>
#include <regex>
#include <mutex>

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <pcap/pcap.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/xt_connlabel.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace std;

class ndPluginLoader;

#include <netifyd.h>
#include <nd-ndpi.h>
#include <nd-json.h>
#include <nd-util.h>
#include <nd-thread.h>
#include <nd-netlink.h>
#include <nd-apps.h>
#include <nd-protos.h>
#include <nd-risks.h>
#include <nd-category.h>
#include <nd-flow.h>
class ndFlowMap;
#include <nd-plugin.h>
#include <nd-flow-map.h>

extern ndApplications *nd_apps;

int main(int argc, char *argv[])
{
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
