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

#ifndef _ND_JSON_H
#define _ND_JSON_H

class ndJsonInitException : public runtime_error
{
public:
    explicit ndJsonInitException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class ndJsonParseException : public runtime_error
{
public:
    explicit ndJsonParseException(const string &what_arg)
        : runtime_error(what_arg) { }
};

void nd_json_to_string(const json &j, string &output, bool pretty = false);

void nd_json_save_to_file(const json &j, const string &filename, bool pretty = false);
void nd_json_save_to_file(const string &j, const string &filename);

void nd_json_agent_hello(string &json_string);
void nd_json_agent_status(json &j);

void nd_json_protocols(string &json_string);

void nd_json_add_interfaces(json &parent);
void nd_json_add_devices(json &parent);
void nd_json_add_stats(json &parent, const ndPacketStats &stats);

typedef vector<string> ndJsonDataChunks;
typedef map<string, ndJsonDataChunks> ndJsonData;

class ndJsonObject
{
public:
    ndJsonObject() {}
    virtual ~ndJsonObject() {}

    virtual void Parse(const string &json_string) = 0;
};

class ndJsonResponse : public ndJsonObject
{
public:
    ndJsonResponse()
        : ndJsonObject(), version(0), resp_code(ndJSON_RESP_NULL),
        update_imf(1), upload_enabled(false) { }

    ndJsonResponse(ndJsonResponseCode code, const string &message)
        : ndJsonObject(), version(0), resp_code(code), resp_message(message),
        update_imf(1), upload_enabled(false) { }

    virtual void Parse(const string &json_string);

    double version;

    ndJsonResponseCode resp_code;
    string resp_message;

    string uuid_site;
    string url_sink;

    unsigned update_imf;
    bool upload_enabled;

    ndJsonData data;

protected:
    void UnserializeData(json &jdata);
};

#endif // _ND_JSON_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
