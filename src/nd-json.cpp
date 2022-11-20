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
#include <stdexcept>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <regex>
#include <mutex>

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-ndpi.h"
#include "nd-base64.h"
#include "nd-packet.h"
#include "nd-json.h"
#include "nd-apps.h"
#include "nd-protos.h"
#include "nd-util.h"

extern ndGlobalConfig nd_config;
extern ndApplications *nd_apps;
extern nd_device nd_devices;
extern nd_interface_addr_map nd_interface_addrs;
extern nd_interface nd_interfaces;
#ifdef _ND_USE_NETLINK
extern nd_netlink_device nd_netlink_devices;
#endif

nd_agent_stats nd_json_agent_stats;

void nd_json_to_string(const json &j, string &output, bool pretty)
{
    output = j.dump(
        pretty ? ND_JSON_INDENT : -1,
        ' ', false, json::error_handler_t::replace
    );

    vector<pair<regex *, string> >::const_iterator i;
    for (i = nd_config.privacy_regex.begin();
        i != nd_config.privacy_regex.end(); i++) {

        string result = regex_replace(output, *((*i).first), (*i).second);
        if (result.size()) output = result;
    }
}

void nd_json_save_to_file(const json &j, const string &filename, bool pretty)
{
    string json_string;
    nd_json_to_string(j, json_string, pretty);
    nd_json_save_to_file(json_string, filename);
}

void nd_json_save_to_file(const string &j, const string &filename)
{
    nd_file_save(filename, j,
        false, ND_JSON_FILE_MODE, ND_JSON_FILE_USER, ND_JSON_FILE_GROUP);
}

void nd_json_agent_hello(string &json_string)
{
    json j;

    j["type"] = "agent_hello";
    j["build_version"] = nd_get_version_and_features();
    j["agent_version"] = strtod(PACKAGE_VERSION, NULL);
    j["json_version"] = (double)ND_JSON_VERSION;

    nd_json_to_string(j, json_string);
    json_string.append("\n");
}

void nd_json_agent_status(json &j)
{
    j["version"] = (double)ND_JSON_VERSION;
    j["timestamp"] = time(NULL);
    j["update_interval"] = nd_config.update_interval;
    j["update_imf"] = nd_config.update_imf;
    j["uptime"] =
        unsigned(nd_json_agent_stats.ts_now.tv_sec - nd_json_agent_stats.ts_epoch.tv_sec);
    j["cpu_cores"] = (unsigned)nd_json_agent_stats.cpus;
    j["cpu_user"] = nd_json_agent_stats.cpu_user;
    j["cpu_user_prev"] = nd_json_agent_stats.cpu_user_prev;
    j["cpu_system"] = nd_json_agent_stats.cpu_system;
    j["cpu_system_prev"] = nd_json_agent_stats.cpu_system_prev;
    j["flow_count"] = nd_json_agent_stats.flows;
    j["flow_count_prev"] = nd_json_agent_stats.flows_prev;
    j["maxrss_kb"] = nd_json_agent_stats.maxrss_kb;
    j["maxrss_kb_prev"] = nd_json_agent_stats.maxrss_kb_prev;
#if (defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)) || \
    (defined(_ND_USE_LIBJEMALLOC) && defined(HAVE_JEMALLOC_JEMALLOC_H))
    j["tcm_kb"] = (unsigned)nd_json_agent_stats.tcm_alloc_kb;
    j["tcm_kb_prev"] = (unsigned)nd_json_agent_stats.tcm_alloc_kb_prev;
#endif // _ND_USE_LIBTCMALLOC || _ND_USE_LIBJEMALLOC
    j["dhc_status"] = nd_json_agent_stats.dhc_status;
    if (nd_json_agent_stats.dhc_status)
        j["dhc_size"] = nd_json_agent_stats.dhc_size;

    j["sink_status"] = nd_json_agent_stats.sink_status;
    j["sink_uploads"] = (ND_UPLOAD_ENABLED) ? true : false;
    if (nd_json_agent_stats.sink_status) {
        j["sink_queue_size_kb"] = nd_json_agent_stats.sink_queue_size / 1024;
        j["sink_queue_max_size_kb"] = nd_config.max_backlog / 1024;
        j["sink_resp_code"] = nd_json_agent_stats.sink_resp_code;
    }
}

void nd_json_protocols(string &json_string)
{
    json j, ja;
    j["type"] = "definitions";

    for (auto &proto : nd_protos) {
        json jo;

        jo["id"] = proto.first;
        jo["tag"] = proto.second;

        ja.push_back(jo);
    }

    j["protocols"] = ja;

    nd_apps_t apps;
    nd_apps->Get(apps);
    for (auto &app : apps) {
        json jo;

        jo["id"] = app.second;
        jo["tag"] = app.first;

        ja.push_back(jo);
    }

    j["applications"] = ja;

    nd_json_to_string(j, json_string);
    json_string.append("\n");
}

void nd_json_add_interfaces(json &parent)
{
    nd_ifaddrs_update(nd_interface_addrs);

    for (nd_interface::const_iterator i = nd_interfaces.begin(); i != nd_interfaces.end(); i++) {
        string iface_name;
        nd_iface_name(i->second, iface_name);

        json jo;

        jo["role"] = (i->first) ? "LAN" : "WAN";

        vector<string> addrs;
        bool found_mac = false;
        string iface_lookup = iface_name;
        auto iface_it = nd_interface_addrs.find(iface_lookup);

        while (iface_it != nd_interface_addrs.end()) {

            for (auto addr_it = iface_it->second->begin();
                addr_it != iface_it->second->end(); addr_it++) {

                string ip;
                if (! found_mac && (*addr_it)->family == AF_LINK) {
                    char mac_addr[ND_STR_ETHALEN + 1];
                    snprintf(mac_addr, sizeof(mac_addr),
                        "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                        (*addr_it)->mac[0], (*addr_it)->mac[1], (*addr_it)->mac[2],
                        (*addr_it)->mac[3], (*addr_it)->mac[4], (*addr_it)->mac[5]
                    );
                    jo["mac"] = mac_addr;
                    found_mac = true;
                }
                else if (((*addr_it)->family == AF_INET
                    || (*addr_it)->family == AF_INET6)
                    && nd_ip_to_string((*addr_it)->ip, ip)) {
                    addrs.push_back(ip);
                }
            }

            auto nld_it = nd_netlink_devices.find(iface_lookup);
            if (nld_it == nd_netlink_devices.end()) break;

            iface_lookup = nld_it->second;
            iface_it = nd_interface_addrs.find(iface_lookup);
        }

        if (! found_mac)
            jo["mac"] = "00:00:00:00:00:00";

        jo["addr"] = addrs;

        parent[iface_name] = jo;
    }
}

void nd_json_add_devices(json &parent)
{
    nd_device_addrs device_addrs;

    for (auto i = nd_devices.begin(); i != nd_devices.end(); i++) {
        if (i->second.first == NULL) continue;

        unique_lock<mutex> lock(*i->second.first);

        for (nd_device_addrs::const_iterator j = i->second.second->begin();
            j != i->second.second->end(); j++) {

            for (vector<string>::const_iterator k = j->second.begin();
                k != j->second.end(); k++) {

                bool duplicate = false;

                if (device_addrs.find(j->first) != device_addrs.end()) {

                    vector<string>::const_iterator l;
                    for (l = device_addrs[j->first].begin();
                        l != device_addrs[j->first].end(); l++) {
                        if ((*k) != (*l)) continue;
                        duplicate = true;
                        break;
                    }
                }

                if (! duplicate)
                    device_addrs[j->first].push_back((*k));
            }
        }

        i->second.second->clear();
    }

    for (nd_device_addrs::const_iterator i = device_addrs.begin();
        i != device_addrs.end(); i++) {

        uint8_t mac_src[ETH_ALEN];
        memcpy(mac_src, i->first.c_str(), ETH_ALEN);
        char mac_dst[ND_STR_ETHALEN + 1];

        sprintf(mac_dst, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
            mac_src[0], mac_src[1], mac_src[2],
            mac_src[3], mac_src[4], mac_src[5]);

        json ja;

        for (vector<string>::const_iterator j = i->second.begin();
            j != i->second.end(); j++) {
            ja.push_back((*j));
        }

        parent[mac_dst] = ja;
    }
}

void nd_json_add_stats(json &parent, const ndPacketStats &stats)
{
    parent["raw"] = stats.pkt.raw;
    parent["ethernet"] = stats.pkt.eth;
    parent["mpls"] = stats.pkt.mpls;
    parent["pppoe"] = stats.pkt.pppoe;
    parent["vlan"] = stats.pkt.vlan;
    parent["fragmented"] = stats.pkt.frags;
    parent["discarded"] = stats.pkt.discard;
    parent["discarded_bytes"] = stats.pkt.discard_bytes;
    parent["largest_bytes"] = stats.pkt.maxlen;
    parent["ip"] = stats.pkt.ip;
    parent["tcp"] = stats.pkt.tcp;
    parent["tcp_seq_error"] = stats.pkt.tcp_seq_error;
    parent["tcp_resets"] = stats.pkt.tcp_resets;
    parent["udp"] = stats.pkt.udp;
    parent["icmp"] = stats.pkt.icmp;
    parent["igmp"] = stats.pkt.igmp;
    parent["ip_bytes"] = stats.pkt.ip_bytes;
    parent["wire_bytes"] = stats.pkt.wire_bytes;
    parent["queue_dropped"] = stats.pkt.queue_dropped;
    parent["capture_dropped"] = stats.pkt.capture_dropped;
    parent["capture_filtered"] = stats.pkt.capture_filtered;

    // XXX: Deprecated
    parent["pcap_recv"] = stats.pkt.raw;
    parent["pcap_drop"] = stats.pkt.capture_dropped;
    parent["pcap_ifdrop"] = 0;
}

void ndJsonStatus::Parse(const string &json_string)
{
    try {
        json j = json::parse(json_string);

        // Extract and validate JSON type
        string type = j["type"].get<string>();

        if (type != "agent_status")
            throw ndJsonParseException("Required type: agent_status");

        uptime = j["uptime"].get<time_t>();
        timestamp = j["timestamp"].get<time_t>();
        update_interval = j["update_interval"].get<unsigned>();
        update_imf = j["update_imf"].get<unsigned>();

        stats.flows = j["flow_count"].get<unsigned>();
        stats.flows_prev = j["flow_count_prev"].get<unsigned>();

        stats.cpus = (long)j["cpu_cores"].get<unsigned>();

        stats.cpu_user = j["cpu_user"].get<double>();
        stats.cpu_user_prev = j["cpu_user_prev"].get<double>();
        stats.cpu_system = j["cpu_system"].get<double>();
        stats.cpu_system_prev = j["cpu_system_prev"].get<double>();

        stats.maxrss_kb = j["maxrss_kb"].get<unsigned>();
        stats.maxrss_kb_prev = j["maxrss_kb_prev"].get<unsigned>();

#if (defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)) || \
    (defined(_ND_USE_LIBJEMALLOC) && defined(HAVE_JEMALLOC_JEMALLOC_H))
        stats.tcm_alloc_kb = j["tcm_kb"].get<unsigned>();
        stats.tcm_alloc_kb_prev = j["tcm_kb_prev"].get<unsigned>();
#endif // _ND_USE_LIBTCMALLOC

        stats.dhc_status = j["dhc_status"].get<bool>();
        if (stats.dhc_status)
            stats.dhc_size = j["dhc_size"].get<unsigned>();

        stats.sink_status = j["sink_status"].get<bool>();
        if (stats.sink_status) {

            stats.sink_uploads = j["sink_uploads"].get<bool>();

            stats.sink_queue_size = j["sink_queue_size_kb"].get<unsigned>();
            stats.sink_queue_size *= 1024;

            sink_queue_max_size_kb = j["sink_queue_max_size_kb"].get<unsigned>();

            unsigned resp_code = j["sink_resp_code"].get<unsigned>();

            if (resp_code > 0 && resp_code < ndJSON_RESP_MAX)
                stats.sink_resp_code = (ndJsonResponseCode)resp_code;
        }
    }
    catch (exception &e) {
        throw ndJsonParseException(e.what());
    }
}

void ndJsonResponse::Parse(const string &json_string)
{
    try {
        if (ND_EXPORT_JSON)
            nd_json_save_to_file(json_string, ND_JSON_FILE_RESPONSE);

        json j = json::parse(json_string);

        // Extract and validate JSON version
        version = j["version"].get<double>();
        if (version > ND_JSON_VERSION) {
            nd_printf("Unsupported JSON response version: %.02f\n", version);
            throw ndJsonParseException("Unsupported JSON response version");
        }

        // Extract and validate response code
        unsigned rc = j["resp_code"].get<unsigned>();
        if (rc == ndJSON_RESP_NULL || rc >= ndJSON_RESP_MAX)
            throw ndJsonParseException("Invalid JSON response code");

        resp_code = (ndJsonResponseCode)rc;

        try {
            resp_message = j["resp_message"].get<string>();
        }
        catch (exception &e) { }

        try {
            uuid_site = j["uuid_site"].get<string>();
        }
        catch (exception &e) { }

        try {
            url_sink = j["url_sink"].get<string>();
        }
        catch (exception &e) { }

        try {
            update_imf = j["update_imf"].get<unsigned>();
        }
        catch (exception &e) { }

        try {
            upload_enabled = j["upload_enabled"].get<bool>();
        }
        catch (exception &e) { }

        auto it_data = j.find("data");
        if (it_data != j.end() && (*it_data) != nullptr)
            UnserializeData((*it_data));

#ifdef _ND_USE_PLUGINS
        auto it_rsp = j.find("plugin_request_service_param");
        if (it_rsp != j.end() && (*it_rsp) != nullptr) {
            UnserializePluginRequest((*it_rsp), plugin_request_service_param);
        }

        auto it_rte = j.find("plugin_request_task_exec");
        if (it_rte != j.end() && (*it_rte) != nullptr)
            UnserializePluginRequest((*it_rte), plugin_request_task_exec);

        auto it_pp = j.find("plugin_params");
        if (it_pp != j.end() && (*it_pp) != nullptr)
            UnserializePluginDispatch((*it_pp));
#endif // _ND_USE_PLUGINS
    }
    catch (ndJsonParseException &e) {
        throw;
    }
    catch (exception &e) {
        throw ndJsonParseException(e.what());
    }
}

void ndJsonResponse::UnserializeData(json &jdata)
{
    for (auto it = jdata.begin(); it != jdata.end(); it++) {
        for (auto it_chunk = (*it).begin(); it_chunk != (*it).end(); it_chunk++) {
            string encoded = (*it_chunk).get<string>();
            data[it.key()].push_back(
                base64_decode(encoded.c_str(), encoded.size())
            );
        }
    }
}

#ifdef _ND_USE_PLUGINS

void ndJsonResponse::UnserializePluginRequest(
    json &jrequest, ndJsonPluginRequest &plugin_request)
{
    for (auto it = jrequest.begin(); it != jrequest.end(); it++)
        plugin_request[it.key()] = (*it).get<string>();
}

void ndJsonResponse::UnserializePluginDispatch(json &jdispatch)
{
    for (auto it = jdispatch.begin(); it != jdispatch.end(); it++) {
        for (auto it_param = (*it).begin(); it_param != (*it).end(); it_param++) {
            string encoded = (*it_param).get<string>();
            plugin_params[it.key()][it_param.key()] =
                base64_decode(encoded.c_str(), encoded.size());
        }
    }
}

#endif // _ND_USE_PLUGINS

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
