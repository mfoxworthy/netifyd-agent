// Netify Daemon
// Copyright (C) 2015-2016 eGloo Incorporated <http://www.egloo.ca>
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

#ifndef _ND_NETLINK_H
#define _ND_NETLINK_H

#define ND_NETLINK_BUFSIZ       4096

#define ND_NETLINK_NETALLOC(e, a)  { \
    e = new ndNetlinkNetworkAddr(a); \
    if (e == NULL) throw ndNetlinkException(strerror(ENOMEM)); }

#define ND_NETLINK_ADDRALLOC(e, a)  { \
    e = new struct sockaddr_storage(a); \
    if (e == NULL) throw ndNetlinkException(strerror(ENOMEM)); }

class ndNetlinkException : public runtime_error
{
public:
    explicit ndNetlinkException(const string &what_arg)
        : runtime_error(what_arg) { }
};

typedef struct ndNetlinkNetworkAddr {
    ndNetlinkNetworkAddr() :
        length(0) { memset(&address, 0, sizeof(struct sockaddr_storage)); }
    ndNetlinkNetworkAddr(const struct sockaddr_storage *addr, uint8_t length = 0) :
        length(length) { memcpy(&address, addr, sizeof(struct sockaddr_storage)); }

    uint8_t length;
    union {
        struct sockaddr_storage address;
        struct sockaddr_storage network;
    };

    inline bool operator==(const ndNetlinkNetworkAddr &n) const;
} ndNetlinkNetworkAddr;

typedef map<string, vector<ndNetlinkNetworkAddr *> > ndNetlinkNetworks;
typedef map<string, vector<struct sockaddr_storage *> > ndNetlinkAddresses;

enum ndNetlinkAddressType
{
    ndNETLINK_ATYPE_UNKNOWN,

    ndNETLINK_ATYPE_LOCALIP,
    ndNETLINK_ATYPE_LOCALNET,
    ndNETLINK_ATYPE_PRIVATE,
    ndNETLINK_ATYPE_MULTICAST,
    ndNETLINK_ATYPE_BROADCAST, // IPv4 "limited broadcast": 255.255.255.255

    ndNETLINK_ATYPE_ERROR,
};

class ndNetlink
{
public:
    ndNetlink(vector<string> *devices);
    virtual ~ndNetlink();

    int GetDescriptor(void) { return nd; }

    void Refresh(void);
    bool ProcessEvent(void);

    ndNetlinkAddressType ClassifyAddress(
        const string &device, const struct sockaddr_storage *addr);

    void Dump(void);

protected:
    bool InNetwork(
        sa_family_t family, uint8_t length,
        const struct sockaddr_storage *addr_host,
        const struct sockaddr_storage *addr_net);

    bool CopyNetlinkAddress(
        sa_family_t family, struct sockaddr_storage &dst, void *src);

    bool ParseMessage(struct rtmsg *rtm, size_t offset,
        string &device, ndNetlinkNetworkAddr &addr);
    bool ParseMessage(struct ifaddrmsg *addrm, size_t offset,
        string &device, struct sockaddr_storage &addr);

    bool AddNetwork(struct nlmsghdr *nlh);
    bool AddNetwork(sa_family_t family,
        const string &type, const string &saddr, uint8_t length);
    bool RemoveNetwork(struct nlmsghdr *nlh);

    bool AddAddress(struct nlmsghdr *nlh);
    bool RemoveAddress(struct nlmsghdr *nlh);

    void PrintAddress(const struct sockaddr_storage *addr);

    int nd;
    unsigned seq;
    struct sockaddr_nl sa;
    uint8_t buffer[ND_NETLINK_BUFSIZ];
    vector<string> *devices;

    ndNetlinkNetworks networks;
    ndNetlinkAddresses addresses;
};

#endif // _ND_NETLINK_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
