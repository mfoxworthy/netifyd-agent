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

#ifndef _ND_APPS_H
#define _ND_APPS_H

#define ND_APP_UNKNOWN  0

typedef uint32_t nd_app_id_t;

class ndApplication
{
public:
    nd_app_id_t id;
    string tag;
    unordered_set<string> domains;
};

typedef map<string, ndApplication *> nd_app_tag_map;
typedef unordered_map<nd_app_id_t, ndApplication *> nd_app_id_map;

class ndApplications
{
public:
    ndApplications();
    virtual ~ndApplications();

    bool Load(const string &filename);
    bool LoadLegacy(const string &filename);

    nd_app_id_t Find(const string &domain);
    nd_app_id_t Find(sa_family_t af, void *addr);

    nd_app_id_t Lookup(const string &tag);
    bool Lookup(const string &tag, ndApplication &app);
    bool Lookup(nd_app_id_t id, ndApplication &app);

protected:
    nd_app_id_map apps;
    nd_app_tag_map app_tags;

    void AddNetwork(nd_app_id_t id, const string &network);

private:
    void *app_networks4, *app_networks6;
};

#endif // _ND_APPS_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
