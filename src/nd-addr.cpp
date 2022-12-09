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

#include <string>
#include <sstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <regex>
#include <mutex>
#include <bitset>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>

#define __FAVOR_BSD 1
#include <netinet/in.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-packet.h"
#include "nd-json.h"
#include "nd-ndpi.h"
#include "nd-sha1.h"
#include "nd-util.h"
#include "nd-addr.h"

extern ndGlobalConfig nd_config;

ndAddr::ndAddr(const string &addr)
    : addr{0}, prefix(0)
{
    string _addr(addr);

    size_t p;
    if ((p = addr.find_first_of("/")) != string::npos) {
        char *ep = NULL;
        prefix = (unsigned)strtoul(
            addr.substr(p + 1).c_str(), &ep, 10
        );

        if (*ep != '\0') {
            nd_dprintf("Invalid IP address prefix value: %s\n",
                addr.substr(p + 1).c_str()
            );
            return;
        }

        _addr.erase(p);
    }

    if (inet_pton(AF_INET,
        _addr.c_str(), &this->addr.in.sin_addr) == 1) {

        if (prefix > 32) {
            nd_dprintf("Invalid IP address prefix value: %u\n",
                prefix
            );
            return;
        }

        this->addr.ss.ss_family = AF_INET;
        return;
    }

    if (inet_pton(AF_INET6,
        _addr.c_str(), &this->addr.in6.sin6_addr) == 1) {

        if (prefix > 128) {
            nd_dprintf("Invalid IP address prefix value: %u\n",
                prefix
            );
            return;
        }

        this->addr.ss.ss_family = AF_INET6;
        return;
    }

    switch (addr.size()) {
    case ND_STR_ETHALEN:
        {
            stringstream ss(addr);
            uint8_t octet = 0, hw_addr[ETH_ALEN] = { 0 };

            do {
                if (! ss.good()) break;

                string byte;
                getline(ss, byte, ':');

                char *ep = NULL;
                hw_addr[octet] = (uint8_t)strtoul(
                    byte.c_str(), &ep, 16
                );

                if (*ep != '\0') {
                    nd_dprintf(
                        "Invalid hardware address, octet #%hhu\n",
                        octet
                    );

                    return;
                }
            }
            while (++octet < ETH_ALEN);

            if (octet == ETH_ALEN)
                CreateHardwareAddress(hw_addr, ETH_ALEN);
        }
        break;
    }
}

ndAddr::ndAddr(
    const struct sockaddr_storage *ss_addr, uint8_t prefix)
    : addr{0}, prefix(0)
{
    switch (ss_addr->ss_family) {
    case AF_INET:
        if (prefix > 32) {
            nd_dprintf("Invalid IP address prefix value: %u\n",
                prefix
            );
            return;
        }
        memcpy(&addr.in, ss_addr, sizeof(struct sockaddr_in));
        break;

    case AF_INET6:
        if (prefix > 128) {
            nd_dprintf("Invalid IP address prefix value: %u\n",
                prefix
            );
            return;
        }
        memcpy(&addr.in6, ss_addr, sizeof(struct sockaddr_in6));
        break;
    }
}

ndAddr::ndAddr(
    const struct sockaddr_in *ss_in, uint8_t prefix)
    : addr{0}, prefix(0)
{
    if (prefix > 32) {
        nd_dprintf("Invalid IP address prefix value: %u\n",
            prefix
        );
        return;
    }

    memcpy(&addr.in, ss_in, sizeof(struct sockaddr_in));
}

ndAddr::ndAddr(
    const struct sockaddr_in6 *ss_in6, uint8_t prefix)
    : addr{0}, prefix(0)
{
    if (prefix > 128) {
        nd_dprintf("Invalid IP address prefix value: %u\n",
            prefix
        );
        return;
    }

    memcpy(&addr.in6, ss_in6, sizeof(struct sockaddr_in6));
}

const string ndAddr::GetString(bool cache)
{
    if (cache && cached_addr.size()) return cached_addr;

    ostringstream os;
    char sa[INET6_ADDRSTRLEN + 4] = { 0 };

    switch (addr.ss.ss_family) {
    case AF_PACKET:
        switch (addr.ll.sll_hatype) {
        case ARPHRD_ETHER:
            {
                char *p = sa;
                for (unsigned i = 0; i < addr.ll.sll_halen
                    && (sa - p) < (INET6_ADDRSTRLEN - 1); i++) {
                    sprintf(p, "%02hhx", addr.ll.sll_addr[i]);
                    p += 2;

                    if (i < (unsigned)(addr.ll.sll_halen - 1)
                        && (sa - p) < (INET6_ADDRSTRLEN - 1)) {
                        *p = ':';
                        p++;
                    }
                }
            }

            os << sa;

            break;
        }
        break;
    case AF_INET:
        inet_ntop(AF_INET,
            (const void *)&addr.in.sin_addr.s_addr,
            sa, INET_ADDRSTRLEN
        );

        os << sa;
        if (prefix > 0) os << "/" << prefix;

        break;
    case AF_INET6:
        inet_ntop(AF_INET6,
            (const void *)&addr.in6.sin6_addr.s6_addr,
            sa, INET6_ADDRSTRLEN
        );

        os << sa;
        if (prefix > 0) os << "/" << (unsigned)prefix;

        break;
    }

    if (cache)
        cached_addr = os.str();

    return os.str();
}

bool ndAddr::CreateHardwareAddress(
    const uint8_t *hw_addr, size_t length)
{
    switch (length) {
    case ETH_ALEN:
        addr.ss.ss_family = AF_PACKET;
        addr.ll.sll_hatype = ARPHRD_ETHER;
        addr.ll.sll_halen = ETH_ALEN;
        memcpy(addr.ll.sll_addr, hw_addr, ETH_ALEN);
        return true;

    default:
        nd_dprintf("Invalid hardware address size: %lu\n", length);
        break;
    }

    return false;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
