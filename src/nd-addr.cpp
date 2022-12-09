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

ndAddrType *nd_addr_info = NULL;

ndAddr::ndAddr(const string &addr)
    : addr{0}, prefix(0)
{
    string _addr(addr);

    size_t p;
    if ((p = addr.find_first_of("/")) != string::npos) {
        char *ep = NULL;
        prefix = (uint8_t)strtoul(
            addr.substr(p + 1).c_str(), &ep, 10
        );

        if (*ep != '\0') {
            nd_dprintf("Invalid IP address prefix length: %s\n",
                addr.substr(p + 1).c_str()
            );
            return;
        }

        _addr.erase(p);
    }

    if (inet_pton(AF_INET,
        _addr.c_str(), &this->addr.in.sin_addr) == 1) {

        if (prefix > 32) {
            nd_dprintf("Invalid IP address prefix length: %hhu\n",
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
            nd_dprintf("Invalid IP address prefix length: %hhu\n",
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
            nd_dprintf("Invalid IP address prefix length: %hhu\n",
                prefix
            );
            return;
        }
        memcpy(&addr.in, ss_addr, sizeof(struct sockaddr_in));
        break;

    case AF_INET6:
        if (prefix > 128) {
            nd_dprintf("Invalid IP address prefix length: %hhu\n",
                prefix
            );
            return;
        }
        memcpy(&addr.in6, ss_addr, sizeof(struct sockaddr_in6));
        break;
    }

    if (prefix) this->prefix = prefix;
}

ndAddr::ndAddr(
    const struct sockaddr_in *ss_in, uint8_t prefix)
    : addr{0}, prefix(0)
{
    if (prefix > 32) {
        nd_dprintf("Invalid IP address prefix length: %hhu\n",
            prefix
        );
        return;
    }

    memcpy(&addr.in, ss_in, sizeof(struct sockaddr_in));
    if (prefix) this->prefix = prefix;
}

ndAddr::ndAddr(
    const struct sockaddr_in6 *ss_in6, uint8_t prefix)
    : addr{0}, prefix(0)
{
    if (prefix > 128) {
        nd_dprintf("Invalid IP address prefix length: %hhu\n",
            prefix
        );
        return;
    }

    memcpy(&addr.in6, ss_in6, sizeof(struct sockaddr_in6));
    if (prefix) this->prefix = prefix;
}

bool ndAddr::MakeString(string &result) const
{
    if (! IsValid()) return false;

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

            result = sa;

            return true;
        }
        break;

    case AF_INET:
        inet_ntop(AF_INET,
            (const void *)&addr.in.sin_addr.s_addr,
            sa, INET_ADDRSTRLEN
        );

        result = sa;
        if (prefix > 0)
            result.append("/" + to_string((size_t)prefix));

        return true;

    case AF_INET6:
        inet_ntop(AF_INET6,
            (const void *)&addr.in6.sin6_addr.s6_addr,
            sa, INET6_ADDRSTRLEN
        );

        result = sa;
        if (prefix > 0)
            result.append("/" + to_string((size_t)prefix));

        return true;
    }

    return false;
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

ndAddrType::ndAddrType()
{
    // Add private networks
    AddAddress(ndAddr::RESERVED, "127.0.0.0/8");
    AddAddress(ndAddr::RESERVED, "10.0.0.0/8");
    AddAddress(ndAddr::RESERVED, "100.64.0.0/10");
    AddAddress(ndAddr::RESERVED, "172.16.0.0/12");
    AddAddress(ndAddr::RESERVED, "192.168.0.0/16");

    AddAddress(ndAddr::RESERVED, "fc00::/7");
    AddAddress(ndAddr::RESERVED, "fd00::/8");
    AddAddress(ndAddr::RESERVED, "fe80::/10");

    // Add multicast networks
    AddAddress(ndAddr::MULTICAST, "224.0.0.0/4");

    AddAddress(ndAddr::MULTICAST, "ff00::/8");

    // Add broadcast addresses
    AddAddress(ndAddr::BROADCAST, "169.254.255.255");
}

bool ndAddrType::AddAddress(
    ndAddr::Type type, const ndAddr &addr, const char *ifname)
{
    if (! addr.IsValid()) {
        nd_printf("Invalid reserved address: %s\n",
            addr.GetString().c_str());
        return false;
    }

    unique_lock<mutex> ul(lock);

    try {
        if (addr.IsEthernet()) {
            string mac;
            if (addr.GetString(mac)) {
                auto it = ether_reserved.find(mac);
                if (it != ether_reserved.end()) {
                    nd_dprintf("Reserved MAC address exists: %s\n",
                        mac.c_str()
                    );
                    return false;
                }
                ether_reserved[mac] = type;
                return true;
            }
        }
        else if (addr.IsIPv4() && ifname == nullptr) {
            ndRadixNetworkEntry<32> entry;
            if (ndRadixNetworkEntry<32>::Create(entry, addr)) {
                ipv4_reserved[entry] = type;
                return true;
            }
        }
        else if (addr.IsIPv6() && ifname == nullptr) {
            ndRadixNetworkEntry<128> entry;
            if (ndRadixNetworkEntry<128>::Create(entry, addr)) {
                ipv6_reserved[entry] = type;
                return true;
            }
        }
        else if (addr.IsIPv4() && ifname != nullptr) {
            ndRadixNetworkEntry<32> entry;
            if (ndRadixNetworkEntry<32>::Create(entry, addr)) {
                ipv4_iface[ifname][entry] = type;
                return true;
            }
        }
        else if (addr.IsIPv6() && ifname != nullptr) {
            ndRadixNetworkEntry<128> entry;
            if (ndRadixNetworkEntry<128>::Create(entry, addr)) {
                ipv6_iface[ifname][entry] = type;
                return true;
            }
        }
    }
    catch (runtime_error &e) {
        nd_dprintf("Error adding reserved address: %s: %s\n",
            addr.GetString().c_str(), e.what());
    }

    return false;
}

void ndAddrType::Classify(ndAddr::Type &type, const ndAddr &addr)
{
    if (addr.IsValid())
        type = ndAddr::OTHER;
    else {
        type = ndAddr::ERROR;
        return;
    }

    if (addr.IsEthernet()) {
        for (uint8_t i = 0x01; i <= 0x0f; i += 0x02) {
            if ((i & addr.addr.ll.sll_addr[0]) != i)
                continue;
            type = ndAddr::MULTICAST;
            return;
        }

        uint8_t sll_addr[sizeof(addr.addr.ll.sll_addr)];

        memset(sll_addr, 0xff, addr.addr.ll.sll_halen);
        if (memcmp(addr.addr.ll.sll_addr, sll_addr,
            addr.addr.ll.sll_halen) == 0) {
            type = ndAddr::BROADCAST;
            return;
        }

        memset(sll_addr, 0, addr.addr.ll.sll_halen);
        if (memcmp(addr.addr.ll.sll_addr, sll_addr,
            addr.addr.ll.sll_halen) == 0) {
            type = ndAddr::NONE;
            return;
        }

        if (ether_reserved.size()) {
            unique_lock<mutex> ul(lock);

            auto it = ether_reserved.find(addr.GetString());
            if (it != ether_reserved.end()) {
                type = it->second;
                return;
            }
        }
    }
    else if (addr.IsIPv4()) {
        if (addr.addr.in.sin_addr.s_addr == 0) {
            type = ndAddr::NONE;
            return;
        }

        if (addr.addr.in.sin_addr.s_addr == 0xffffffff) {
            type = ndAddr::BROADCAST;
            return;
        }

        for (auto &iface : ipv4_iface) {
            ndRadixNetworkEntry<32> entry;
            if (ndRadixNetworkEntry<32>::CreateQuery(entry, addr)) {

                unique_lock<mutex> ul(lock);

                nd_rn4_atype::iterator it;
                if ((it = iface.second.longest_match(entry))
                    != iface.second.end()) {
                    type = it->second;
                    return;
                }
            }
        }

        ndRadixNetworkEntry<32> entry;
        if (ndRadixNetworkEntry<32>::CreateQuery(entry, addr)) {

            unique_lock<mutex> ul(lock);

            nd_rn4_atype::iterator it;
            if ((it = ipv4_reserved.longest_match(entry))
                != ipv4_reserved.end()) {
                type = it->second;
                return;
            }
        }
    }
    else if (addr.IsIPv6()) {
        if (addr.addr.in6.sin6_addr.s6_addr32[0] == 0
            && addr.addr.in6.sin6_addr.s6_addr32[1] == 0
            && addr.addr.in6.sin6_addr.s6_addr32[2] == 0
            && addr.addr.in6.sin6_addr.s6_addr32[3]) {
            type = ndAddr::NONE;
            return;
        }

        for (auto &iface : ipv6_iface) {
            ndRadixNetworkEntry<128> entry;
            if (ndRadixNetworkEntry<128>::CreateQuery(entry, addr)) {

                unique_lock<mutex> ul(lock);

                nd_rn6_atype::iterator it;
                if ((it = iface.second.longest_match(entry))
                    != iface.second.end()) {
                    type = it->second;
                    return;
                }
            }
        }

        ndRadixNetworkEntry<128> entry;
        if (ndRadixNetworkEntry<128>::CreateQuery(entry, addr)) {

            unique_lock<mutex> ul(lock);

            nd_rn6_atype::iterator it;
            if ((it = ipv6_reserved.longest_match(entry))
                != ipv6_reserved.end()) {
                type = it->second;
                return;
            }
        }
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
