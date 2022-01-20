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

typedef enum {
    ndCAT_TYPE_APP,
    ndCAT_TYPE_PROTO,

    ndCAT_TYPE_MAX
} ndCategoryType;

class ndCategories;

class ndCategory
{
protected:
    friend class ndCategories;

    typedef map<string, unsigned> index_tag;
    typedef set<unsigned> set_id;
    typedef map<unsigned, set_id> index_cat;
    typedef pair<unsigned, set_id> index_cat_insert;

    index_tag tag;
    index_cat index;

    bool Load(json &jdata);

    ndCategoryType type;
};

class ndCategories
{
public:
    ndCategories() : last_update(0) {
        // XXX: Must be in order of enum ndCategoryType, without gaps.
        categories[ndCAT_TYPE_APP] = ndCategory();
        categories[ndCAT_TYPE_PROTO] = ndCategory();
    };

    bool Load(void);
    bool Load(ndCategoryType type, json &jdata);
    bool Save(void);
    void Dump(ndCategoryType type = ndCAT_TYPE_MAX);

    time_t GetLastUpdate(void) { return last_update; }

    bool Lookup(ndCategoryType type, unsigned cat_id, unsigned id);
    bool Lookup(ndCategoryType type, const string &cat_tag, unsigned id);

protected:
    time_t last_update;
    map<ndCategoryType, ndCategory> categories;
};

#endif // _ND_CATEGORY_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
