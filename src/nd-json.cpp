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
#include <bitset>
#include <atomic>

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>

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
#include "nd-ndpi.h"
#include "nd-base64.h"
#include "nd-risks.h"
#include "nd-serializer.h"
#include "nd-packet.h"
#include "nd-json.h"
#include "nd-util.h"
#include "nd-addr.h"
#include "nd-apps.h"
#include "nd-protos.h"

extern ndGlobalConfig nd_config;
extern ndApplications *nd_apps;
extern ndInterfaces nd_interfaces;
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
    j["agent_version"] = PACKAGE_VERSION;
    j["build_version"] = nd_get_version_and_features();
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
    static vector<string> keys = { "addr" };

    for (auto &i : nd_interfaces) {
        json jo;
        i.second.Encode(jo);
        i.second.EncodeAddrs(jo, keys);

        string iface_name;
        nd_iface_name(i.second.ifname, iface_name);

        parent[iface_name] = jo;
    }
}

void nd_json_add_devices(json &parent)
{
    for (auto &i : nd_interfaces)
        i.second.EncodeEndpoints(i.second.LastEndpointSnapshot(), parent);
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
