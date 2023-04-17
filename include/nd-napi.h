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

#ifndef _ND_NAPI_H
#define _ND_NAPI_H

#define _ND_NAPI_RETRY_TTL  5

class ndNetifyApiThread : public ndThread, public ndInstanceClient
{
public:
    ndNetifyApiThread();
    virtual ~ndNetifyApiThread();

    virtual void *Entry(void);

    void AppendData(const char *data, size_t length)
    {
        try {
            body_data.append(data, length);
        } catch (exception &e) {
            throw ndThreadException(e.what());
        }
    }

    void ParseHeader(const string &header_raw);

protected:
    unsigned Get(const string &url);

    CURL *ch;
    struct curl_slist *headers_tx;
    map<string, string> headers_rx;
    string body_data;

    ndCategories categories;
};

#endif // _ND_NAPI_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
