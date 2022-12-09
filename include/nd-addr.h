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
    enum ndAddrType
    {
        UNKNOWN,

        LOCALIP,
        LOCALNET,
        PRIVATE,
        MULTICAST,
        BROADCAST,

        ERROR,
    };

    ndAddr(uint8_t prefix = 0) : addr{0}, prefix(prefix) { };

    ndAddr(const string &addr);
    ndAddr(const uint8_t *hw_addr, size_t length)
        : addr{0}, prefix(0) {
        CreateHardwareAddress(hw_addr, length);
    }

    ndAddr(const struct sockaddr_storage *ss_addr,
        uint8_t prefix = 0);
    ndAddr(const struct sockaddr_storage &ss_addr,
        uint8_t prefix = 0) : ndAddr(&ss_addr, prefix) { }

    ndAddr(const struct sockaddr_in *ss_in,
        uint8_t prefix = 0);
    ndAddr(const struct sockaddr_in &ss_in,
        uint8_t prefix = 0) : ndAddr(&ss_in, prefix) { }

    ndAddr(const struct sockaddr_in6 *ss_in6,
        uint8_t prefix = 0);
    ndAddr(const struct sockaddr_in6 &ss_in6,
        uint8_t prefix = 0) : ndAddr(&ss_in6, prefix) { }

    inline bool IsValid(void) const {
        return (addr.ss.ss_family != AF_UNSPEC);
    }
    inline bool HasValidPrefix(void) const {
        return (prefix > 0 && (
            (addr.ss.ss_family == AF_INET && prefix <= 32)
            || (addr.ss.ss_family == AF_INET6 && prefix <= 128)
        ));
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

    const string GetString(bool cache = true);
    inline void GetString(string &addr, bool cache = true) {
        addr = GetString(cache);
    }

    inline bool operator==(const ndAddr &a) const {
        if (a.prefix != prefix) return false;
        if (a.addr.ss.ss_family != addr.ss.ss_family) return false;

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

    union {
        struct sockaddr_storage ss;
        struct sockaddr_ll ll;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    } addr;

    uint8_t prefix;

    string cached_addr;

protected:
    bool CreateHardwareAddress(
        const uint8_t *hw_addr, size_t length);
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

    bool GetString(sa_family_t af, string &ip) const {
        ndAddr a((uint8_t)prefix_len);
        switch (af) {
        case AF_INET:
            a.addr.in.sin_addr.s_addr = htonl(addr.to_ulong());
            break;
        case AF_INET6:
            for (auto i = 0; i < 4; i++) {
                bitset<32> b;
                for (auto j = 0; j < 32; j++)
                    b[j] = addr[i * 32 + j];
                a.addr.in6.sin6_addr.s6_addr32[3 - i] = htonl(b.to_ulong());
            }
            break;
        default:
            return false;
        }
        a.GetString(ip, false);
        return true;
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

#endif // _ND_ADDR_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
