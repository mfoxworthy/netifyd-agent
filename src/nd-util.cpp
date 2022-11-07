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

#include <cstddef>
#include <cstdlib>
#include <cstdarg>
#include <string>
#include <stdexcept>
#include <iostream>
#include <locale>
#include <iomanip>
#include <sstream>
#include <vector>
#include <map>
#include <deque>
#include <unordered_map>
#include <regex>
#include <memory>
#include <mutex>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#if defined(BSD4_4)
#include <sys/user.h>
#include <sys/sysctl.h>
#endif

#define __FAVOR_BSD 1
#include <netinet/in.h>

#if defined(__linux__)
#include <linux/if_packet.h>
#elif defined(BSD4_4)
#include <net/if_dl.h>
#endif

#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#ifdef _ND_USE_WATCHDOGS
#include <time.h>
#endif
#include <pwd.h>
#include <grp.h>
#include <libgen.h>
#include <dirent.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>

#include <net/if.h>

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-ndpi.h"
#include "nd-sha1.h"
#include "nd-json.h"
#include "nd-util.h"

extern ndGlobalConfig nd_config;

static mutex nd_printf_mutex;

ndException::ndException(const string &where_arg, const string &what_arg) throw()
    : runtime_error(what_arg), where_arg(where_arg), what_arg(what_arg), message(NULL)
{
    ostringstream os;
    os << where_arg << ": " << what_arg;
    message = strdup(os.str().c_str());
}

ndException::~ndException() throw()
{
    if (message != NULL) free((void *)message);
}

const char *ndException::what() const throw()
{
    return message;
}

ndSystemException::ndSystemException(
    const string &where_arg, const string &what_arg, int why_arg) throw()
    : runtime_error(what_arg),
    where_arg(where_arg), what_arg(what_arg), why_arg(why_arg), message(NULL)
{
    ostringstream os;
    os << where_arg << ": " << what_arg << ": " << strerror(why_arg);
    message = strdup(os.str().c_str());
}

ndSystemException::~ndSystemException() throw()
{
    if (message != NULL) free((void *)message);
}

const char *ndSystemException::what() const throw()
{
    return message;
}

void *nd_mem_alloc(size_t size)
{
    return malloc(size);
}

void nd_mem_free(void *ptr)
{
    free(ptr);
}

void nd_printf(const char *format, ...)
{
    if (ND_QUIET) return;

    va_list ap;
    va_start(ap, format);
    nd_printf(format, ap);
    va_end(ap);
}

void nd_printf(const char *format, va_list ap)
{
    if (ND_QUIET) return;

    unique_lock<mutex> lock(nd_printf_mutex);

    vsyslog(LOG_DAEMON | LOG_INFO, format, ap);
}

void nd_dprintf(const char *format, ...)
{
    if (! ND_DEBUG) return;

    va_list ap;
    va_start(ap, format);
    nd_dprintf(format, ap);
    va_end(ap);
}

void nd_dprintf(const char *format, va_list ap)
{
    if (! ND_DEBUG) return;

    unique_lock<mutex> lock(nd_printf_mutex);

    vfprintf(stderr, format, ap);
}

void nd_flow_printf(const char *format, ...)
{
    unique_lock<mutex> lock(nd_printf_mutex);

    va_list ap;
    va_start(ap, format);
    vfprintf(nd_config.h_flow, format, ap);
    va_end(ap);
}

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
void nd_ndpi_debug_printf(uint32_t protocol, void *ndpi,
    ndpi_log_level_t level, const char *file, const char *func, unsigned line,
    const char *format, ...)
{
    if (ND_DEBUG && (ND_DEBUG_NDPI || level == NDPI_LOG_ERROR)) {

        unique_lock<mutex> lock(nd_printf_mutex);

        va_list ap;
        va_start(ap, format);

        fprintf(stdout, "[nDPI:%08x:%p:%s]: %s/%s:%d: ", protocol, ndpi,
            (level == NDPI_LOG_ERROR) ? "ERROR" :
                (level == NDPI_LOG_TRACE) ? "TRACE" :
                    (level == NDPI_LOG_DEBUG) ? "DEBUG" :
                        (level == NDPI_LOG_DEBUG_EXTRA) ? "DEXTRA" :
                            "UNK???",
            file, func, line
        );

        vfprintf(stdout, format, ap);
        va_end(ap);
    }
}
#endif // NDPI_ENABLE_DEBUG_MESSAGES

void nd_print_address(const struct sockaddr_storage *addr)
{
    int rc;
    char _addr[NI_MAXHOST];

    switch (addr->ss_family) {
    case AF_INET:
        rc = getnameinfo((const struct sockaddr *)addr, sizeof(struct sockaddr_in),
            _addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        break;
    case AF_INET6:
        rc = getnameinfo((const struct sockaddr *)addr, sizeof(struct sockaddr_in6),
            _addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        break;
    default:
        nd_dprintf("(unsupported AF:%x)", addr->ss_family);
        return;
    }

    if (rc == 0)
        nd_dprintf("%s", _addr);
    else
        nd_dprintf("???");
}

void nd_print_binary(uint32_t byte)
{
    uint32_t i;
    char b[sizeof(byte) * 8 + 1];

    b[0] = '\0';
    for (i = 0x80000000; i > 0; i >>= 1)
        strcat(b, ((byte & i) == i) ? "1" : "0");

    nd_dprintf("%s", b);
}

void nd_print_number(ostringstream &os, uint64_t value, bool units_binary)
{
    float fvalue = value;

    os.str("");
    //os << setiosflags(ios::fixed) << setw(14) << setprecision(3);
    os << setw(8) << setprecision(3);

    if (units_binary) {
        if (fvalue >= 1099511627776.0f) {
            fvalue /= 1099511627776.0f;
            os << fvalue << setw(4) << " TiB";
        }
        else if (fvalue >= 1073741824.0f) {
            fvalue /= 1073741824.0f;
            os << fvalue << setw(4) << " GiB";
        }
        else if (fvalue >= 1048576.0f) {
            fvalue /= 1048576.0f;
            os << fvalue << setw(4) << " MiB";
        }
        else if (fvalue >= 1024.0f) {
            fvalue /= 1024.0f;
            os << fvalue << setw(4) << " KiB";
        }
        else {
            os << fvalue << setw(4) << " ";
        }
    }
    else {
        if (fvalue >= 1000000000000.0f) {
            fvalue /= 1000000000000.0f;
            os << fvalue << setw(4) << " TP ";
        }
        else if (fvalue >= 1000000000.0f) {
            fvalue /= 1000000000.0f;
            os << fvalue << setw(4) << " GP ";
        }
        else if (fvalue >= 1000000.0f) {
            fvalue /= 1000000.0f;
            os << fvalue << setw(4) << " MP ";
        }
        else if (fvalue >= 1000.0f) {
            fvalue /= 1000.0f;
            os << fvalue << setw(4) << " KP ";
        }
        else {
            os << fvalue << setw(4) << " ";
        }
    }
}

void nd_ltrim(string &s, unsigned char c)
{
    s.erase(s.begin(), find_if(s.begin(), s.end(), [c](unsigned char ch) {
        if (c == 0) return !isspace(ch);
        else return (ch != c);
    }));
}

void nd_rtrim(string &s, unsigned char c)
{
    s.erase(find_if(s.rbegin(), s.rend(), [c](unsigned char ch) {
        if (c == 0) return !isspace(ch);
        else return (ch != c);
    }).base(), s.end());
}

void nd_trim(string &s, unsigned char c)
{
    nd_ltrim(s, c);
    nd_rtrim(s, c);
}

int nd_sha1_file(const string &filename, uint8_t *digest)
{
    sha1 ctx;
    int fd = open(filename.c_str(), O_RDONLY);
    uint8_t buffer[ND_SHA1_BUFFER], _digest[SHA1_DIGEST_LENGTH];
    ssize_t bytes;

    sha1_init(&ctx);

    if (fd < 0) {
        nd_printf("Unable to hash file: %s: %s\n",
            filename.c_str(), strerror(errno));
        return -1;
    }

    do {
        bytes = read(fd, buffer, ND_SHA1_BUFFER);

        if (bytes > 0)
            sha1_write(&ctx, (const char *)buffer, bytes);
        else if (bytes < 0) {
            nd_printf("Unable to hash file: %s: %s\n",
                filename.c_str(), strerror(errno));
            close(fd);
            return -1;
        }
    }
    while (bytes != 0);

    close(fd);
    memcpy(digest, sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);

    return 0;
}

void nd_sha1_to_string(const uint8_t *digest_bin, string &digest_str)
{
    char _digest[SHA1_DIGEST_LENGTH * 2 + 1];
    char *p = _digest;

    for (int i = 0; i < SHA1_DIGEST_LENGTH; i++, p += 2)
        sprintf(p, "%02x", digest_bin[i]);

    digest_str.assign(_digest);
}

bool nd_string_to_mac(const string &src, uint8_t *mac)
{
    if (src.size() != ND_STR_ETHALEN) return false;

    uint8_t *p = mac;
    const char *s = src.c_str();

    for (int i = 0; i < ND_STR_ETHALEN; i += 3, p++) {
        if (sscanf(s + i, "%2hhx", p) != 1) return false;
    }

    return true;
}

sa_family_t nd_string_to_ip(const string &src, sockaddr_storage *ip)
{
    sa_family_t family = AF_UNSPEC;
    struct sockaddr_in *ipv4 = reinterpret_cast<struct sockaddr_in *>(ip);
    struct sockaddr_in6 *ipv6 = reinterpret_cast<struct sockaddr_in6 *>(ip);

    if (inet_pton(AF_INET, src.c_str(), &ipv4->sin_addr) == 1)
        family = AF_INET;
    else if (inet_pton(AF_INET6, src.c_str(), &ipv6->sin6_addr) == 1)
        family = AF_INET6;

    return family;
}

bool nd_ip_to_string(sa_family_t af, const void *addr, string &dst)
{
    char ip[INET6_ADDRSTRLEN];

    switch (af) {
    case AF_INET:
        inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, addr, ip, INET6_ADDRSTRLEN);
        break;
    default:
        return false;
    }

    dst.assign(ip);

    return true;
}

bool nd_ip_to_string(const sockaddr_storage &ip, string &dst)
{
    const struct sockaddr_in *ipv4 = reinterpret_cast<const struct sockaddr_in *>(&ip);
    const struct sockaddr_in6 *ipv6 = reinterpret_cast<const struct sockaddr_in6 *>(&ip);

    switch (ip.ss_family) {
    case AF_INET:
        return nd_ip_to_string(
            AF_INET, (const void *)&ipv4->sin_addr.s_addr, dst
        );
    case AF_INET6:
        return nd_ip_to_string(
            AF_INET6, (const void *)&ipv6->sin6_addr.s6_addr, dst
        );
    default:
        return false;
    }

    return false;
}

void nd_iface_name(const string &iface, string &result)
{
    result = iface;
    size_t p = string::npos;
    if ((p = iface.find_first_of(",")) != string::npos)
        result = iface.substr(0, p);
}

void nd_capture_filename(const string &iface, string &result)
{
    result.clear();
    size_t p = string::npos;
    if ((p = iface.find_first_of(",")) != string::npos)
        result = iface.substr(p + 1);
}

bool nd_is_ipaddr(const char *ip)
{
    struct in_addr addr4;
    struct in6_addr addr6;

    if (inet_pton(AF_INET, ip, &addr4) == 1) return true;
    return (inet_pton(AF_INET6, ip, &addr6) == 1) ? true : false;
}

void nd_private_ipaddr(uint8_t index, struct sockaddr_storage &addr)
{
    int rc = -1;
    ostringstream os;

    if (addr.ss_family == AF_INET) {
        os << ND_PRIVATE_IPV4 << (int)index;
        struct sockaddr_in *sa = reinterpret_cast<struct sockaddr_in *>(&addr);
        rc = inet_pton(AF_INET, os.str().c_str(), &sa->sin_addr);
    }
    else if (addr.ss_family == AF_INET6) {
        os << ND_PRIVATE_IPV6 << hex << (int)index;
        struct sockaddr_in6 *sa = reinterpret_cast<struct sockaddr_in6 *>(&addr);
        rc = inet_pton(AF_INET6, os.str().c_str(), &sa->sin6_addr);
    }

    switch (rc) {
    case -1:
        nd_dprintf("Invalid private address family.\n");
        break;
    case 0:
        nd_dprintf("Invalid private address: %s\n", os.str().c_str());
        break;
    }
}

bool nd_load_uuid(string &uuid, const char *path, size_t length)
{
    struct stat sb;
    char _uuid[length + 1];

    if (stat(path, &sb) == -1) {
        if (errno != ENOENT) {
            nd_printf("Error loading uuid: %s: %s\n",
                path, strerror(errno));
        }
        return false;
    }

    if (! S_ISREG(sb.st_mode)) {
        nd_printf("Error loading uuid: %s: %s\n",
            path, "Not a regular file");
        return false;
    }

    if (sb.st_mode & S_IXUSR) {
        FILE *ph = popen(path, "r");

        if (ph == NULL) {
            if (ND_DEBUG || errno != ENOENT) {
                nd_printf("Error loading uuid from pipe: %s: %s\n",
                    path, strerror(errno));
            }
            return false;
        }

        size_t bytes = 0;

        bytes = fread((void *)_uuid, 1, length, ph);

        int rc = pclose(ph);

        if (bytes <= 0 || rc != 0) {
            nd_printf("Error loading uuid from pipe: %s: %s: %d\n",
                path, "Invalid pipe read", rc);
            return false;
        }

        _uuid[bytes - 1] = '\0';
    }
    else {
        FILE *fh = fopen(path, "r");

        if (fh == NULL) {
            if (ND_DEBUG || errno != ENOENT) {
                nd_printf("Error loading uuid from file: %s: %s\n",
                    path, strerror(errno));
            }
            return false;
        }

        if (fread((void *)_uuid, 1, length, fh) != length) {
            fclose(fh);
            nd_printf("Error reading uuid from file: %s: %s\n",
                path, strerror(errno));
            return false;
        }

        fclose(fh);

        _uuid[length] = '\0';
    }

    uuid.assign(_uuid);

    nd_rtrim(uuid);

    return true;
}

bool nd_save_uuid(const string &uuid, const char *path, size_t length)
{
    FILE *fh = fopen(path, "w");

    if (fh == NULL) {
        nd_printf("Error saving uuid: %s: %s\n", path, strerror(errno));
        return false;
    }

    if (fwrite((const void *)uuid.c_str(),
        1, length, fh) != length) {
        fclose(fh);
        nd_printf("Error writing uuid: %s: %s\n", path, strerror(errno));
        return false;
    }

    fclose(fh);
    return true;
}

bool nd_load_sink_url(string &url)
{
    char _url[ND_URL_SINK_LEN];
    FILE *fh = fopen(ND_URL_SINK_PATH, "r");

    if (fh == NULL) {
        if (ND_DEBUG || errno != ENOENT)
            nd_printf("Error loading URL: %s: %s\n", ND_URL_SINK_PATH, strerror(errno));
        return false;
    }

    if (fgets(_url, ND_URL_SINK_LEN, fh) == NULL) {
        fclose(fh);
        nd_printf("Error reading URL: %s: %s\n", ND_URL_SINK_PATH, strerror(errno));
        return false;
    }

    fclose(fh);
    url.assign(_url);

    return true;
}

bool nd_save_sink_url(const string &url)
{
    FILE *fh = fopen(ND_URL_SINK_PATH, "w");

    if (fh == NULL) {
        nd_printf("Error saving URL: %s: %s\n", ND_URL_SINK_PATH, strerror(errno));
        return false;
    }

    if (fputs(url.c_str(), fh) < 0) {
        fclose(fh);
        nd_printf("Error writing URL: %s: %s\n", ND_URL_SINK_PATH, strerror(errno));
        return false;
    }

    fclose(fh);
    return true;
}

void nd_seed_rng(void)
{
    FILE *fh = fopen("/dev/urandom", "r");
    unsigned int seed = (unsigned int)time(NULL);

    if (fh == NULL)
        nd_printf("Error opening random device: %s\n", strerror(errno));
    else {
        if (fread((void *)&seed, sizeof(unsigned int), 1, fh) != 1)
            nd_printf("Error reading from random device: %s\n", strerror(errno));
        fclose(fh);
    }

    srand(seed);
}

void nd_generate_uuid(string &uuid)
{
    int digit = 0;
    deque<char> result;
    uint64_t input = 623714775;
    const char *clist = { "0123456789abcdefghijklmnpqrstuvwxyz" };
    ostringstream os;

    input = (uint64_t)rand();
    input += (uint64_t)rand() << 32;

    while (input != 0) {
        result.push_front(toupper(clist[input % strlen(clist)]));
        input /= strlen(clist);
    }

    for (size_t i = result.size(); i < 8; i++)
        result.push_back('0');

    while (result.size() && digit < 8) {
        os << result.front();
        result.pop_front();
        if (digit == 1) os << "-";
        if (digit == 3) os << "-";
        if (digit == 5) os << "-";
        digit++;
    }

    uuid = os.str();
}

string nd_get_version_and_features(void)
{
    string os;
    nd_os_detect(os);

    ostringstream ident;
    ident <<
        PACKAGE_NAME << "/" << GIT_RELEASE << " (" << os << "; " << _ND_HOST_CPU;

    if (ND_USE_CONNTRACK) ident << "; conntrack";
    if (ND_USE_NETLINK) ident << "; netlink";
    if (ND_USE_DHC) ident << "; dns-cache";
#ifdef _ND_USE_PLUGINS
    ident << "; plugins";
#endif
#ifdef _ND_USE_LIBTCMALLOC
    ident << "; tcmalloc";
#endif
#ifdef _ND_USE_LIBJEMALLOC
    ident << "; jemalloc";
#endif
    if (ND_SSL_USE_TLSv1) ident << "; ssl-tlsv1";
    if (! ND_SSL_VERIFY) ident << "; ssl-no-verify";
#ifdef _ND_USE_INOTIFY
    ident << "; inotify";
#endif
#ifdef HAVE_WORKING_REGEX
    ident << "; regex";
#endif
    ident << ")";

    return ident.str();
}

bool nd_parse_app_tag(const string &tag, unsigned &id, string &name)
{
    id = 0;
    name.clear();

    size_t p;
    if ((p = tag.find_first_of(".")) != string::npos) {
        id = (unsigned)strtoul(tag.substr(0, p).c_str(), NULL, 0);
        name = tag.substr(p + 1);

        return true;
    }

    return false;
}

#ifdef _ND_USE_WATCHDOGS
int nd_touch(const string &filename)
{
    int fd;
    struct timespec now[2];

    fd = open(filename.c_str(), O_WRONLY | O_CREAT | O_NONBLOCK | O_NOCTTY,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

    if (fd < 0) return fd;

    clock_gettime(CLOCK_REALTIME, &now[0]);
    clock_gettime(CLOCK_REALTIME, &now[1]);

    if (futimens(fd, now) < 0) return -1;

    close(fd);

    return 0;
}
#endif

int nd_file_load(const string &filename, string &data)
{
    struct stat sb;
    int fd = open(filename.c_str(), O_RDONLY);

    if (fd < 0) {
        if (errno != ENOENT)
            throw runtime_error(strerror(errno));
        else {
            nd_dprintf("Unable to load file: %s: %s\n",
                filename.c_str(), strerror(errno));
            return -1;
        }
    }

    if (flock(fd, LOCK_SH) < 0) {
        close(fd);
        throw runtime_error(strerror(errno));
    }

    if (fstat(fd, &sb) < 0) {
        close(fd);
        throw runtime_error(strerror(errno));
    }

    if (sb.st_size == 0)
        data.clear();
    else {
        auto buffer = make_shared<vector<uint8_t>>(sb.st_size);
        if (read(fd, (void *)buffer->data(), sb.st_size) < 0)
            throw runtime_error(strerror(errno));
        data.assign((const char *)buffer->data(), sb.st_size);
    }

    flock(fd, LOCK_UN);
    close(fd);

    return 0;
}

void nd_file_save(const string &filename,
    const string &data, bool append, mode_t mode, const char *user, const char *group)
{
    int fd = open(filename.c_str(), O_WRONLY);
    struct passwd *owner_user = NULL;
    struct group *owner_group = NULL;

    if (fd < 0) {
        if (errno != ENOENT)
            throw runtime_error(strerror(errno));
        fd = open(filename.c_str(), O_WRONLY | O_CREAT, mode);
        if (fd < 0)
            throw runtime_error(strerror(errno));

        if (user != NULL) {
            owner_user = getpwnam(user);
            if (owner_user == NULL)
                throw runtime_error(strerror(errno));
        }

        if (group != NULL) {
            owner_group = getgrnam(group);
            if (owner_group == NULL)
                throw runtime_error(strerror(errno));
        }

        if (fchown(fd,
            (owner_user != NULL) ? owner_user->pw_uid : -1,
            (owner_group != NULL) ? owner_group->gr_gid : -1) < 0)
            throw runtime_error(strerror(errno));
    }

    if (flock(fd, LOCK_EX) < 0)
        throw runtime_error(strerror(errno));

    if (lseek(fd, 0, (! append) ? SEEK_SET: SEEK_END) < 0)
        throw runtime_error(strerror(errno));

    if (! append && ftruncate(fd, 0) < 0)
        throw runtime_error(strerror(errno));

    if (write(fd, (const void *)data.c_str(), data.length()) < 0)
        throw runtime_error(strerror(errno));

    flock(fd, LOCK_UN);
    close(fd);
}

int nd_save_response_data(const char *filename, const ndJsonDataChunks &data)
{
    try {
        int chunks = 0;
        for (ndJsonDataChunks::const_iterator i = data.begin(); i != data.end(); i++)
            nd_file_save(filename, (*i), (0 != chunks++));
    }
    catch (runtime_error &e) {
        nd_printf("Error saving file: %s: %s\n", filename, e.what());
        return -1;
    }

    return 0;
}

int nd_ifreq(const string &name, unsigned long request, struct ifreq *ifr)
{
    int fd, rc = -1;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        nd_printf("%s: error creating ifreq socket: %s\n",
            name.c_str(), strerror(errno));
            return rc;
    }

    memset(ifr, '\0', sizeof(struct ifreq));
    strncpy(ifr->ifr_name, name.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, request, (char *)ifr) == -1) {
        nd_dprintf("%s: error sending interface request: %s\n",
            name.c_str(), strerror(errno));
    }
    else rc = 0;

    close(fd);
    return rc;
}

int nd_ifaddrs(nd_interface_addr_map &addr_map)
{
    int count = 0;
    struct ifaddrs *ifaddr, *ifa;
    nd_interface_addr_map::iterator i;
    nd_interface_addr_array *addrs;

    if (getifaddrs(&ifaddr) == -1) {
        nd_printf("getifaddrs: %s\n", strerror(errno));
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        i = addr_map.find(ifa->ifa_name);
        if (i == addr_map.end()) {
            nd_interface_addr_insert addr_iter;

            addrs = new nd_interface_addr_array;
            if (addrs == NULL)
                throw runtime_error(strerror(ENOMEM));
            addr_iter = addr_map.insert(nd_interface_addr_pair(ifa->ifa_name, addrs));
            i = addr_iter.first;
        }
        else
            addrs = i->second;

        struct ndInterfaceAddress *addr = new struct ndInterfaceAddress;
        if (addr == NULL) throw runtime_error(strerror(ENOMEM));
        memset(addr, 0, sizeof(struct ndInterfaceAddress));

        addr->family = ifa->ifa_addr->sa_family;

        switch (addr->family) {
        case AF_LINK:
            memset(addr->mac, 0, ETH_ALEN);
#if defined(__linux__)
            {
                struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
                memcpy(addr->mac, s->sll_addr, ETH_ALEN);
            }
#elif defined(BSD4_4)
            {
                struct sockaddr_dl *s = (struct sockaddr_dl *)ifa->ifa_addr;
                memcpy(addr->mac, s->sdl_data + s->sdl_nlen, ETH_ALEN);
            }
#endif
            addrs->push_back(addr);
            count++;
            break;
        case AF_INET:
            memcpy(&addr->ip, ifa->ifa_addr, sizeof(struct sockaddr_in));
            addrs->push_back(addr);
            count++;
            break;
        case AF_INET6:
            memcpy(&addr->ip, ifa->ifa_addr, sizeof(struct sockaddr_in6));
            addrs->push_back(addr);
            count++;
            break;
        default:
            delete addr;
        }
    }

    freeifaddrs(ifaddr);

    return count;
}

int nd_ifaddrs_update(nd_interface_addr_map &addr_map)
{
    nd_ifaddrs_free(addr_map);
    return nd_ifaddrs(addr_map);
}

void nd_ifaddrs_free(nd_interface_addr_map &addr_map)
{
    nd_interface_addr_map::iterator i;

    for (i = addr_map.begin(); i != addr_map.end(); i++) {
        vector<struct ndInterfaceAddress *>::iterator a;
        for (a = i->second->begin(); a != i->second->end(); a++)
            delete (*a);
        delete (i->second);
    }

    addr_map.clear();
}

bool nd_ifaddrs_get_mac(
    nd_interface_addr_map &addr_map,
    const string &name, uint8_t *addr)
{
    nd_interface_addr_map::iterator i = addr_map.find(name);

    if (i == addr_map.end()) return false;

    vector<struct ndInterfaceAddress *>::iterator a;
    for (a = i->second->begin(); a != i->second->end(); a++) {
        if ((*a)->family == AF_LINK) {
            memcpy(addr, (*a)->mac, ETH_ALEN);
            return true;
        }
    }

    return false;
}

#if defined(__linux__)
pid_t nd_is_running(pid_t pid, const char *exe_base)
{
    pid_t rc = -1;
    struct stat sb;
    char link_path[1024];
    ssize_t r;
    ostringstream proc_exe_link;

    proc_exe_link << "/proc/" << pid << "/exe";

    if (lstat(proc_exe_link.str().c_str(), &sb) == -1) {
        if (errno != ENOENT) {
            nd_printf("%s: lstat: %s: %s\n",
                __PRETTY_FUNCTION__, proc_exe_link.str().c_str(), strerror(errno));
            return rc;
        }

        return 0;
    }

    r = readlink(proc_exe_link.str().c_str(), link_path, sizeof(link_path));

    if (r != -1) {
        link_path[r] = '\0';

        if (strncmp(basename(link_path), exe_base, strlen(exe_base)))
            rc = 0;
        else
            rc = pid;
    }
    else {
        nd_printf("%s: readlink: %s: %s\n",
            __PRETTY_FUNCTION__, proc_exe_link.str().c_str(), strerror(errno));
    }

    return rc;
}
#elif defined(BSD4_4)
pid_t nd_is_running(pid_t pid, const char *exe_base)
{
    int mib[4];
    pid_t rc = -1;
    size_t length = 4;
    char pathname[PATH_MAX];

    if (sysctlnametomib("kern.proc.pathname", mib, &length) < 0) {
        nd_printf("%s: sysctlnametomib: %s: %s\n",
            __PRETTY_FUNCTION__, "kern.proc.pathname", strerror(errno));
        return rc;
    }

    mib[3] = pid;
    length = sizeof(pathname);

    if (sysctl(mib, 4, pathname, &length, NULL, 0) == -1) {
        nd_printf("%s: sysctl: %s(%ld): %s\n",
            __PRETTY_FUNCTION__, "kern.proc.pathname", pid, strerror(errno));
    }
    else if (length > 0) {
        char *pathname_base = basename(pathname);
        length = strlen(pathname_base);
        if (strlen(exe_base) < length) length = strlen(exe_base);

        if (strncmp(pathname_base, exe_base, length) == 0)
            rc = pid;
        else
            rc = 0;
    }

    return rc;
}
#else
#error "Unsupported platform, not Linux or BSD >= 4.4."
#endif

int nd_file_exists(const char *path)
{
    struct stat sb;

    if (stat(path, &sb) == -1) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    return 1;
}

#define _ND_UT_MIN  (60)
#define _ND_UT_HOUR (_ND_UT_MIN * 60)
#define _ND_UT_DAY  (_ND_UT_HOUR * 24)

void nd_uptime(time_t ut, string &uptime)
{
    time_t seconds = ut;
    time_t days = 0, hours = 0, minutes = 0;

    if (seconds > 0) {
        days = seconds / _ND_UT_DAY;
        seconds -= days * _ND_UT_DAY;
    }

    if (seconds > 0) {
        hours = seconds / _ND_UT_HOUR;
        seconds -= hours * _ND_UT_HOUR;
    }

    if (seconds > 0) {
        minutes = seconds / _ND_UT_MIN;
        seconds -= minutes * _ND_UT_MIN;
    }

    ostringstream os;
    ios os_state(NULL);
    os_state.copyfmt(os);

    os << days << "d";
    os << " " << setfill('0') << setw(2) << hours;
    os.copyfmt(os_state);
    os << ":" << setfill('0') << setw(2) << minutes;
    os.copyfmt(os_state);
    os << ":" << setfill('0') << setw(2) << seconds;

    uptime.assign(os.str());
}

int nd_functions_exec(const string &func, string &output)
{
    ostringstream os;
    os << "sh -c \". " << ND_DATADIR << "/functions.sh && " << func << "\" 2>&1";

    int rc = -1;
    FILE *ph = popen(os.str().c_str(), "r");

    if (ph != NULL) {
        char buffer[64];
        size_t bytes = 0;

        do {
            if ((bytes = fread(buffer, 1, sizeof(buffer), ph)) > 0)
                output.append(buffer, bytes);
        }
        while (bytes > 0);

        rc = pclose(ph);
    }

    return rc;
}

void nd_os_detect(string &os)
{
    string output;
    int rc = nd_functions_exec("detect_os", output);

    if (rc == 0 && output.size()) {
        const char *ws = "\n";
        output.erase(output.find_last_not_of(ws) + 1);
        os.assign(output);
    }
    else
        os = "unknown";
}

ndLogDirectory::ndLogDirectory(
    const string &path, const string &prefix, const string &suffix,
    bool overwrite)
    : path(path), prefix(prefix), suffix(suffix), overwrite(overwrite),
    hf_cur(NULL)
{
    struct stat sb;

    if (stat(path.c_str(), &sb) == -1) {
        if (errno == ENOENT) {
            if (mkdir(path.c_str(), 0750) != 0)
                throw ndSystemException(__PRETTY_FUNCTION__, path, errno);
        }
        else
            throw ndSystemException(__PRETTY_FUNCTION__, path, errno);

        if (! S_ISDIR(sb.st_mode))
            throw ndSystemException(__PRETTY_FUNCTION__, path, EINVAL);
    }
}

ndLogDirectory::~ndLogDirectory()
{
    Close();
}

FILE *ndLogDirectory::Open(void)
{
    if (hf_cur != NULL) {
        nd_dprintf("Log file already open; close or discard first: %s\n",
            filename.c_str());
        return NULL;
    }

    if (! overwrite) {
        time_t now = time(NULL);
        struct tm tm_now;

        tzset();
        localtime_r(&now, &tm_now);

        char stamp[_ND_LOG_FILE_STAMP_SIZE];
        strftime(stamp, _ND_LOG_FILE_STAMP_SIZE, _ND_LOG_FILE_STAMP, &tm_now);

        filename = prefix + stamp + suffix;
    }
    else
        filename = prefix + suffix;

    string full_path = path + "/." + filename;

    if (! (hf_cur = fopen(full_path.c_str(), "w"))) {
        nd_dprintf("Error opening log file: %s: %s\n",
            full_path.c_str(), strerror(errno));
        return NULL;
    }

    return hf_cur;
}

void ndLogDirectory::Close(void)
{
    if (hf_cur != NULL) {

        fclose(hf_cur);

        string src = path + "/." + filename;
        string dst = path + "/" + filename;

        if (overwrite) unlink(dst.c_str());

        if (rename(src.c_str(), dst.c_str()) != 0) {
            nd_dprintf("Error renaming log file: %s -> %s: %s\n",
                src.c_str(), dst.c_str(), strerror(errno));
        }

        hf_cur = NULL;
    }
}

void ndLogDirectory::Discard(void)
{
    if (hf_cur != NULL) {

        string full_path = path + "/." + filename;

        nd_dprintf("Discarding log file: %s\n", full_path.c_str());

        fclose(hf_cur);

        unlink(full_path.c_str());

        hf_cur = NULL;
    }
}

void nd_regex_error(const regex_error &e, string &error)
{
    switch (e.code()) {
    case regex_constants::error_collate:
        error = "The expression contains an invalid collating element name";
        break;
    case regex_constants::error_ctype:
        error = "The expression contains an invalid character class name";
        break;
    case regex_constants::error_escape:
        error = "The expression contains an invalid escaped character or a trailing escape";
        break;
    case regex_constants::error_backref:
        error = "The expression contains an invalid back reference";
        break;
    case regex_constants::error_brack:
        error = "The expression contains mismatched square brackets ('[' and ']')";
        break;
    case regex_constants::error_paren:
        error = "The expression contains mismatched parentheses ('(' and ')')";
        break;
    case regex_constants::error_brace:
        error = "The expression contains mismatched curly braces ('{' and '}')";
        break;
    case regex_constants::error_badbrace:
        error = "The expression contains an invalid range in a {} expression";
        break;
    case regex_constants::error_range:
        error = "The expression contains an invalid character range (e.g. [b-a])";
        break;
    case regex_constants::error_space:
        error = "There was not enough memory to convert the expression into a finite state machine";
        break;
    case regex_constants::error_badrepeat:
        error = "one of *?+{ was not preceded by a valid regular expression";
        break;
    case regex_constants::error_complexity:
        error = "The complexity of an attempted match exceeded a predefined level";
        break;
    case regex_constants::error_stack:
        error = "There was not enough memory to perform a match";
        break;
    default:
        error = e.what();
        break;
    }
}

bool nd_scan_dotd(const string &path, vector<string> &files)
{
    DIR *dh = opendir(path.c_str());

    if (dh == NULL) {
        nd_printf("Error opening directory: %s: %s\n",
            path.c_str(), strerror(errno));
        return false;
    }

    long dname_max = pathconf(path.c_str(), _PC_NAME_MAX);
    if (dname_max == -1) dname_max = 255;
    size_t entry_size = offsetof(struct dirent, d_name) + dname_max + 1;

    struct dirent *dentry = reinterpret_cast<struct dirent *>(
        new uint8_t[entry_size]
    );
    unique_ptr<struct dirent, void(*)(struct dirent *p)> entry(
        dentry, [](struct dirent *p) {
        delete [] (uint8_t *)p;
    });

    int rc;
    struct dirent *result = NULL;
    while (! (rc = readdir_r(dh, dentry, &result))) {
        if (result == NULL) break;
        if (
            (
                result->d_type != DT_LNK &&
                result->d_type != DT_REG &&
                result->d_type != DT_UNKNOWN
            )
            || ! isdigit(result->d_name[0])) continue;
        files.push_back(result->d_name);
    }

    closedir(dh);

    return (rc == 0);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
