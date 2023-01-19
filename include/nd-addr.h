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

#ifndef _ND_ADDR_H
#define _ND_ADDR_H

class ndAddr
{
public:
    enum Type
    {
        atNONE,
        atLOCAL,
        atLOCALNET,
        atRESERVED,
        atMULTICAST,
        atBROADCAST,
        atOTHER,

        atERROR = 0x7f,
    };

    ndAddr(uint8_t prefix = 0)
        : addr{0}, prefix(prefix) { }

    ndAddr(const string &addr)
        : addr{0}, prefix(0) {
        Create(*this, addr);
    }

    ndAddr(const uint8_t *hw_addr, size_t length = ETH_ALEN)
        : addr{0}, prefix(0) {
        Create(*this, hw_addr, length);
    }

    ndAddr(const struct sockaddr_storage *ss_addr,
        uint8_t prefix = 0)
        : addr{0}, prefix(0) {
        Create(*this, ss_addr, prefix);
    }
    ndAddr(const struct sockaddr_storage &ss_addr,
        uint8_t prefix = 0) : ndAddr(&ss_addr, prefix) { }

    ndAddr(const struct sockaddr_in *ss_in,
        uint8_t prefix = 32)
        : addr{0}, prefix(0) {
        Create(*this, ss_in, prefix);
    }
    ndAddr(const struct sockaddr_in &ss_in,
        uint8_t prefix = 32) : ndAddr(&ss_in, prefix) { }

    ndAddr(const struct sockaddr_in6 *ss_in6,
        uint8_t prefix = 128)
        : addr{0}, prefix(0) {
        Create(*this, ss_in6, prefix);
    }
    ndAddr(const struct sockaddr_in6 &ss_in6,
        uint8_t prefix = 128) : ndAddr(&ss_in6, prefix) { }

    ndAddr(const struct in_addr *in_addr, uint8_t prefix = 32)
        : addr{0}, prefix(0) {
        Create(*this, in_addr, prefix);
    }
    ndAddr(const struct in_addr &in_addr, uint8_t prefix = 32)
        : ndAddr(&in_addr, prefix) { }

    ndAddr(const struct in6_addr *in6_addr, uint8_t prefix = 128)
        : addr{0}, prefix(0) {
        Create(*this, in6_addr, prefix);
    }
    ndAddr(const struct in6_addr &in6_addr, uint8_t prefix = 128)
        : ndAddr(&in6_addr, prefix) { }

    static bool Create(ndAddr &a, const string &addr);

    static bool Create(ndAddr &a,
        const uint8_t *hw_addr, size_t length);

    static bool Create(ndAddr &a,
        const struct sockaddr_storage *ss_addr, uint8_t prefix = 0);

    static bool Create(ndAddr &a,
        const struct sockaddr_in *ss_in, uint8_t prefix = 32);

    static bool Create(ndAddr &a,
        const struct sockaddr_in6 *ss_in6, uint8_t prefix = 128);

    static bool Create(ndAddr &a,
        const struct in_addr *in_addr, uint8_t prefix = 32);

    static bool Create(ndAddr &a,
        const struct in6_addr *in6_addr, uint8_t prefix = 128);

    const uint8_t *GetAddress(void) const;
    size_t GetAddressSize(void) const;

    uint16_t GetPort(bool byte_swap = true) const;
    bool SetPort(uint16_t port);

    inline bool IsValid(void) const {
        return (addr.ss.ss_family != AF_UNSPEC);
    }
    inline bool HasValidPrefix(void) const {
        return (prefix > 0 && (
            (addr.ss.ss_family == AF_INET && prefix <= 32)
            || (addr.ss.ss_family == AF_INET6 && prefix <= 128)
        ));
    }
    inline bool IsNetwork(void) const {
        if (! HasValidPrefix()) return false;
        if (addr.ss.ss_family == AF_INET && prefix != 32)
            return true;
        return (addr.ss.ss_family == AF_INET6 && prefix != 128);
    }
    inline bool IsEthernet(void) const {
        return (addr.ss.ss_family == AF_PACKET
            && addr.ll.sll_hatype == ARPHRD_ETHER
            && addr.ll.sll_halen == ETH_ALEN
        );
    }
    inline bool IsIP(void) const {
        return (
            addr.ss.ss_family == AF_INET
            || addr.ss.ss_family == AF_INET6
        );
    }
    inline bool IsIPv4(void) const {
        return (
            addr.ss.ss_family == AF_INET
        );
    }
    inline bool IsIPv6(void) const {
        return (
            addr.ss.ss_family == AF_INET6
        );
    }

    enum MakeFlags {
        mfNONE = 0x0,
        mfPREFIX = 0x1,
        mfPORT = 0x2,

        mfALL = (mfPREFIX | mfPORT)
    };

    static bool MakeString(const ndAddr &a, string &result, uint8_t flags = mfALL);

    inline const string GetString() const { return cached_addr; }

    inline bool operator==(const ndAddr &a) const {
        if (a.prefix != prefix)
            return false;
        if (a.addr.ss.ss_family != addr.ss.ss_family)
            return false;

        switch (addr.ss.ss_family) {
        case AF_PACKET:
            return (memcmp(&addr.ll,
                &a.addr.ll, sizeof(struct sockaddr_ll)) == 0);
        case AF_INET:
            return (memcmp(&addr.in,
                &a.addr.in, sizeof(struct sockaddr_in)) == 0);
        case AF_INET6:
            return (memcmp(&addr.in6,
                &a.addr.in6, sizeof(struct sockaddr_in6)) == 0);
        }
        return false;
    }

    inline bool operator!=(const ndAddr &a) const {
        return !(a == *this);
    }

    struct ndAddrHash {
        template <class T>
        inline void hash_combine(size_t &seed, const T &v) const {
            hash<T> hasher;
            seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }

        size_t operator()(const ndAddr &a) const {
            size_t ss_hash = 0;

            switch (a.addr.ss.ss_family) {
            case AF_PACKET:
               for (int i = 0; i < ETH_ALEN; i++) {
                    hash_combine<uint8_t>(
                        ss_hash, a.addr.ll.sll_addr[i]
                    );
                }
                break;
            case AF_INET:
                hash_combine<uint32_t>(
                    ss_hash, a.addr.in.sin_addr.s_addr
                );
                break;
            case AF_INET6:
                hash_combine<uint32_t>(
                    ss_hash, a.addr.in6.sin6_addr.s6_addr32[0]
                );
                hash_combine<uint32_t>(
                    ss_hash, a.addr.in6.sin6_addr.s6_addr32[1]
                );
                hash_combine<uint32_t>(
                    ss_hash, a.addr.in6.sin6_addr.s6_addr32[2]
                );
                hash_combine<uint32_t>(
                    ss_hash, a.addr.in6.sin6_addr.s6_addr32[3]
                );
                break;
            }

            return ss_hash;
        }
    };

    struct ndAddrHashAll {
        template <class T>
        inline void hash_combine(size_t &seed, const T &v) const {
            hash<T> hasher;
            seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }

        size_t operator()(const ndAddr &a) const {
            size_t ss_hash = 0;

            hash_combine<uint8_t>(ss_hash, a.prefix);
            hash_combine<uint16_t>(ss_hash, a.addr.ss.ss_family);

            switch (a.addr.ss.ss_family) {
            case AF_PACKET:
                for (int i = 0; i < ETH_ALEN; i++) {
                    hash_combine<uint8_t>(
                        ss_hash, a.addr.ll.sll_addr[i]
                    );
                }
                break;
            case AF_INET:
                hash_combine<uint16_t>(
                    ss_hash, a.addr.in.sin_port
                );
                hash_combine<uint32_t>(
                    ss_hash, a.addr.in.sin_addr.s_addr
                );
                break;
            case AF_INET6:
                hash_combine<uint16_t>(
                    ss_hash, a.addr.in6.sin6_port
                );
                hash_combine<uint32_t>(
                    ss_hash, a.addr.in6.sin6_addr.s6_addr32[0]
                );
                hash_combine<uint32_t>(
                    ss_hash, a.addr.in6.sin6_addr.s6_addr32[1]
                );
                hash_combine<uint32_t>(
                    ss_hash, a.addr.in6.sin6_addr.s6_addr32[2]
                );
                hash_combine<uint32_t>(
                    ss_hash, a.addr.in6.sin6_addr.s6_addr32[3]
                );
                break;
            }

            return ss_hash;
        }
    };

    struct ndAddrEqual {
        bool operator()(const ndAddr& a1, const ndAddr& a2) const {
            if (a1.addr.ss.ss_family != a2.addr.ss.ss_family)
                return false;

            switch (a1.addr.ss.ss_family) {
            case AF_PACKET:
                return (memcmp(&a1.addr.ll,
                    &a2.addr.ll, sizeof(struct sockaddr_ll)) == 0);
                break;
            case AF_INET:
                return (memcmp(
                    &a1.addr.in.sin_addr,
                    &a2.addr.in.sin_addr,
                    sizeof(struct in_addr)) == 0);
                break;
            case AF_INET6:
                return (memcmp(
                    &a1.addr.in6.sin6_addr,
                    &a2.addr.in6.sin6_addr,
                    sizeof(struct in6_addr)) == 0);
                break;
            }

            return false;
        }
    };

    struct ndAddrEqualAll {
        bool operator()(const ndAddr& a1, const ndAddr& a2) const {
            return (a1 == a2);
        }
    };

    union {
        struct sockaddr_storage ss;
        struct sockaddr_ll ll;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    } addr;

    uint8_t prefix;

    string cached_addr;
};

template<size_t N>
bool operator<(const bitset<N> &x, const bitset<N> &y)
{
    for (int i = N-1; i >= 0; i--) {
        if (x[i] ^ y[i]) return y[i];
    }

    return false;
}

template <size_t N>
class ndRadixNetworkEntry {
public:
    bitset<N> addr;
    size_t prefix_len;

    ndRadixNetworkEntry() : prefix_len(0) { }

    static bool Create(
        ndRadixNetworkEntry<N> &entry, const ndAddr &addr) {

        if (! addr.IsValid()) {
            nd_dprintf("Invalid radix address.\n");
            return false;
        }

        entry.prefix_len = (size_t)(
            (addr.prefix == 0) ? N : addr.prefix
        );

        if (entry.prefix_len > N) {
            nd_dprintf("Invalid radix address prefix length.\n");
            return false;
        }

        bitset<N> mask;

        size_t shift = N - entry.prefix_len;
        if (shift < N) {
            mask.set();
            for (size_t i = 0; i < shift; i++) mask.flip(i);
        }

        switch (N) {
        case 32: // AF_INET
            entry.addr = ntohl(addr.addr.in.sin_addr.s_addr);
            entry.addr &= mask;
            return true;

        case 128: // AF_INET6
            entry.addr |= ntohl(
                addr.addr.in6.sin6_addr.s6_addr32[0]
            );
            entry.addr <<= 32;
            entry.addr |= ntohl(
                addr.addr.in6.sin6_addr.s6_addr32[1]
            );
            entry.addr <<= 32;
            entry.addr |= ntohl(
                addr.addr.in6.sin6_addr.s6_addr32[2]
            );
            entry.addr <<= 32;
            entry.addr |= ntohl(
                addr.addr.in6.sin6_addr.s6_addr32[3]
            );
            entry.addr &= mask;
            return true;
        }

        nd_dprintf("Unsupported address size: %lu.\n", N);
        return false;
    }

    static void Create(
        ndRadixNetworkEntry<N> &entry, const string &addr) {
        Create(ndAddr(addr));
    }

    static bool CreateQuery(
        ndRadixNetworkEntry<N> &entry, const ndAddr &addr) {

        if (! addr.IsValid()) {
            nd_dprintf("Invalid radix address.\n");
            return false;
        }

        entry.prefix_len = N;

        switch (N) {
        case 32: // AF_INET
            entry.addr = ntohl(addr.addr.in.sin_addr.s_addr);
            return true;

        case 128: // AF_INET6
            entry.addr |= ntohl(
                addr.addr.in6.sin6_addr.s6_addr32[0]
            );
            entry.addr <<= 32;
            entry.addr |= ntohl(
                addr.addr.in6.sin6_addr.s6_addr32[1]
            );
            entry.addr <<= 32;
            entry.addr |= ntohl(
                addr.addr.in6.sin6_addr.s6_addr32[2]
            );
            entry.addr <<= 32;
            entry.addr |= ntohl(
                addr.addr.in6.sin6_addr.s6_addr32[3]
            );
            return true;
        }

        nd_dprintf("Unsupported address size: %lu.\n", N);
        return false;
    }

    bool operator[] (int n) const {
        return addr[(N - 1) - n];
    }

    bool operator== (const ndRadixNetworkEntry &rhs) const {
        return prefix_len == rhs.prefix_len && addr == rhs.addr;
    }

    bool operator< (const ndRadixNetworkEntry &rhs) const {
        if (addr == rhs.addr)
            return prefix_len < rhs.prefix_len;
        else
            return addr < rhs.addr;
    }

    bool GetString(string &ip) const {
        ndAddr a((uint8_t)prefix_len);
        switch (N) {
        case 32: // AF_INET
            a.addr.in.sin_addr.s_addr = htonl(addr.to_ulong());
            break;
        case 128: // AF_INET6
            for (auto i = 0; i < 4; i++) {
                bitset<N> b;
                for (size_t j = 0; j < N; j++)
                    b[j] = addr[i * N + j];
                a.addr.in6.sin6_addr.s6_addr32[3 - i] = htonl(b.to_ulong());
            }
            break;
        default:
            return false;
        }
        return ndAddr::MakeString(a, ip);
    }
};

template <size_t N>
int radix_length(const ndRadixNetworkEntry<N> &entry)
{
    return (int)entry.prefix_len;
}

template <size_t N>
ndRadixNetworkEntry<N> radix_substr(
    const ndRadixNetworkEntry<N> &entry, int offset, int length
) {
    bitset<N> mask;

    if (length == N)
        mask = 0;
    else {
        mask = 1;
        mask <<= length;
    }

    mask -= 1;
    mask <<= N - length - offset;

    ndRadixNetworkEntry<N> result;
    result.addr = (entry.addr & mask) << offset;
    result.prefix_len = length;

    return result;
}

template<size_t N>
bitset<N> &operator-=(bitset<N> &x, const size_t y)
{
    bool borrow = false;
    bitset<N> const _y(y);

    for (size_t i = 0; i < N; i++) {
        if (borrow) {
            if (x[i]) {
                x[i] = _y[i];
                borrow = _y[i];
            }
            else {
                x[i] = ! _y[i];
                borrow = true;
            }
        }
        else {
            if (x[i]) {
                x[i] = ! _y[i];
                borrow = false;
            }
            else {
                x[i] = _y[i];
                borrow = _y[i];
            }
        }
    }

    return x;
}

template <size_t N>
ndRadixNetworkEntry<N> radix_join(
    const ndRadixNetworkEntry<N> &x,
    const ndRadixNetworkEntry<N> &y
) {
    ndRadixNetworkEntry<N> result;

    result.addr = x.addr;
    result.addr |= y.addr >> x.prefix_len;
    result.prefix_len = x.prefix_len + y.prefix_len;

    return result;
}

template <size_t N>
ndRadixNetworkEntry<N> radix_join(
    const ndRadixNetworkEntry<N> &x,
    const ndRadixNetworkEntry<N> &y
);

typedef radix_tree<ndRadixNetworkEntry<32>, ndAddr::Type> nd_rn4_atype;
typedef radix_tree<ndRadixNetworkEntry<128>, ndAddr::Type> nd_rn6_atype;

class ndAddrType
{
public:
    ndAddrType();

    bool AddAddress(ndAddr::Type type,
        const ndAddr &addr, const char *ifname = nullptr);
    inline bool AddAddress(ndAddr::Type type,
        const string &addr, const char *ifname = nullptr) {
        return AddAddress(type, ndAddr(addr), ifname);
    }

    bool RemoveAddress(
        const ndAddr &addr, const char *ifname = nullptr);
    inline bool RemoveAddress(
        const string &addr, const char *ifname = nullptr) {
        return RemoveAddress(ndAddr(addr), ifname);
    }

    void Classify(
        ndAddr::Type &type, const ndAddr &addr);
    inline void Classify(
        ndAddr::Type &type, const string &addr) {
        Classify(type, ndAddr(addr));
    }

protected:
    mutex lock;

    unordered_map<string, ndAddr::Type> ether_reserved;

    nd_rn4_atype ipv4_reserved;
    nd_rn6_atype ipv6_reserved;

    unordered_map<string, nd_rn4_atype> ipv4_iface;
    unordered_map<string, nd_rn6_atype> ipv6_iface;
};

typedef unordered_set<ndAddr, ndAddr::ndAddrHash, ndAddr::ndAddrEqual> ndInterfaceAddrs;

class ndInterfaceAddr : public ndSerializer
{
public:
    ndInterfaceAddr() : lock(nullptr) {
        lock = new mutex;
        if (lock == nullptr) {
            throw ndSystemException(
                __PRETTY_FUNCTION__, "new mutex", ENOMEM
            );
        }
    }

    ndInterfaceAddr(const ndAddr &a) : lock(nullptr) {
        lock = new mutex;
        if (lock == nullptr) {
            throw ndSystemException(
                __PRETTY_FUNCTION__, "new mutex", ENOMEM
            );
        }
        Push(a);
    }

    ndInterfaceAddr(const ndInterfaceAddr &iface) :
        addrs(iface.addrs) {
        lock = new mutex;
        if (lock == nullptr) {
            throw ndSystemException(
                __PRETTY_FUNCTION__, "new mutex", ENOMEM
            );
        }
    }

    virtual ~ndInterfaceAddr() {
        if (lock != nullptr) delete lock;
    }

    inline void Clear(bool locked = true) {
        if (locked) lock->lock();
        addrs.clear();
        if (locked) lock->unlock();
    }

    inline bool Push(const ndAddr &addr) {
        unique_lock<mutex> ul(*lock);
        auto result = addrs.insert(addr);
        return result.second;
    }

    template <class T>
    void Encode(T &output, const string &key) const {
        if (addrs.empty()) return;
        unique_lock<mutex> ul(*lock);
        vector<string> addresses;
        for (auto& a : addrs)
            addresses.push_back(a.GetString());
        serialize(output, { key }, addresses);
    }

    inline bool FindFirstOf(
        sa_family_t family, ndAddr& addr) const {

        unique_lock<mutex> ul(*lock);
        for (auto& it : addrs) {
            if (it.addr.ss.ss_family != family) continue;
            addr = it;
            return true;
        }
        return false;
    }

    inline bool FindAllOf(
        const vector<sa_family_t> &families,
        vector<string> &results) const {

        size_t count = results.size();
        unique_lock<mutex> ul(*lock);

        for (auto& it : addrs) {
            if (find_if(
                families.begin(), families.end(),
                [it](const sa_family_t &f) {
                    return (it.addr.ss.ss_family == f);
                }
            ) == families.end()) continue;

            results.push_back(it.GetString());
        }

        return (results.size() > count);
    }

protected:
    ndInterfaceAddrs addrs;
    mutex *lock;
};

typedef unordered_map<ndAddr, ndInterfaceAddr, ndAddr::ndAddrHash, ndAddr::ndAddrEqual> ndInterfaceEndpoints;

class ndInterface;
typedef map<string, ndInterface> ndInterfaces;

class ndInterface : public ndSerializer
{
public:
    ndInterface(
        const string &ifname,
        bool internal = true, unsigned instances = 1)
        : ifname(ifname), ifname_peer(ifname),
        internal(internal), instances(instances), lock(nullptr) {
        lock = new mutex;
        if (lock == nullptr) {
            throw ndSystemException(
                __PRETTY_FUNCTION__, "new mutex", ENOMEM
            );
        }
    }

    ndInterface(const ndInterface &iface) :
        ifname(iface.ifname), ifname_peer(iface.ifname_peer),
        internal(iface.internal), instances(iface.instances) {
        lock = new mutex;
        if (lock == nullptr) {
            throw ndSystemException(
                __PRETTY_FUNCTION__, "new mutex", ENOMEM
            );
        }
    }

    virtual ~ndInterface() {
        if (lock != nullptr) delete lock;
    }

    static size_t UpdateAddrs(ndInterfaces &interfaces);

    size_t UpdateAddrs(const struct ifaddrs *if_addrs);

    template <class T>
    void Encode(T &output) const {

        serialize(output, { "role" }, (internal) ? "LAN" : "WAN");

        ndAddr mac;
        if (addrs.FindFirstOf(AF_PACKET, mac))
            serialize(output, { "mac" }, mac.GetString());
        else
            serialize(output, { "mac" }, "00:00:00:00:00:00");
    }

    template <class T>
    void EncodeAddrs(T &output, const vector<string> &keys, const string &delim = ",") const {
        vector<string> ip_addrs;
        if (addrs.FindAllOf({ AF_INET, AF_INET6 }, ip_addrs))
            serialize(output, keys, ip_addrs, delim);
    }

    inline bool PushEndpoint(const ndAddr &mac, const ndAddr &ip) {
        unique_lock<mutex> ul(*lock);
        auto result = endpoints.emplace(
            make_pair(mac, ndInterfaceAddr(ip))
        );

        if (! result.second)
            return result.first->second.Push(ip);

        return true;
    }

    inline void ClearEndpoints(void) {
        unique_lock<mutex> ul(*lock);
        for (auto &it : endpoints) it.second.Clear();
        endpoints.clear();
    }

    template <class T>
    inline void EncodeEndpoints(T &output) const {
        unique_lock<mutex> ul(*lock);
        for (auto &i : endpoints)
            i.second.Encode(output,  i.first.GetString());
    }

    inline void GetEndpoints(
        unordered_map<string, unordered_set<string>> &output) const {
        unique_lock<mutex> ul(*lock);
        for (auto& i : endpoints) {
            vector<string> ip_addrs;
            if (! i.second.FindAllOf(
                { AF_INET, AF_INET6 }, ip_addrs)) continue;

            for (auto& j : ip_addrs)
                output[i.first.GetString()].insert(j);
        }
    }

    string ifname;
    string ifname_peer;
    bool internal;
    unsigned instances;

protected:
    ndInterfaceAddr addrs;
    ndInterfaceEndpoints endpoints;
    mutex *lock;
};

#endif // _ND_ADDR_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
