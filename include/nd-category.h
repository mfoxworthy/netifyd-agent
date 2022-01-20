// Netify Agent
// Copyright (C) 2015-2021 eGloo Incorporated <http://www.egloo.ca>
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

#ifndef _ND_CATEGORY_H
#define _ND_CATEGORY_H

class ndCategory
{
public:
    typedef enum {
        ndCAT_APP,
        ndCAT_PROTO,

        ndCAT_MAX
    } ndCategoryType;

    ndCategory() : last_update(0) { }

    bool Load(void);
    bool Save(void);
    void Dump(const string &oper);

    void Parse(ndCategoryType type, json &jdata);

    bool Lookup(ndCategoryType type, const string &name, unsigned id);

    time_t GetLastUpdate(void) { return last_update; }

protected:
    time_t last_update;

    typedef set<unsigned> nd_id_set;
    typedef unordered_map <string, nd_id_set> nd_name_lookup;
    typedef pair<string, nd_id_set> nd_name_lookup_pair;

    nd_name_lookup apps, protos;
};

#endif // _ND_CATEGORY_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
