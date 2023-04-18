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

#ifndef _ND_CATEGORY_H
#define _ND_CATEGORY_H

#define ND_CAT_UNKNOWN      0
#define ND_DOMAIN_UNKNOWN   0

typedef enum {
    ndCAT_TYPE_APP,
    ndCAT_TYPE_PROTO,

    ndCAT_TYPE_MAX
} ndCategoryType;

class ndCategories;

typedef unsigned nd_cat_id_t;

class ndCategory
{
public:
    typedef map<string, nd_cat_id_t> index_tag;
    typedef set<unsigned> set_id;
    typedef map<nd_cat_id_t, set_id> index_cat;
    typedef pair<nd_cat_id_t, set_id> index_cat_insert;

protected:
    friend class ndCategories;

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

    bool IsMember(ndCategoryType type, nd_cat_id_t cat_id, unsigned id);
    bool IsMember(ndCategoryType type, const string &cat_tag, unsigned id);

    nd_cat_id_t Lookup(ndCategoryType type, unsigned id);
    nd_cat_id_t LookupTag(ndCategoryType type, const string &tag);
    nd_cat_id_t ResolveTag(ndCategoryType type, unsigned id, string &tag);

    bool GetTagIndex(ndCategoryType type, ndCategory::index_tag &index) {
        unique_lock<mutex> ul(lock);

        auto it = categories.find(type);
        if (it == categories.end()) return false;
        index.insert(it->second.tag.begin(), it->second.tag.end());
        return true;
    }

protected:
    mutex lock;
    time_t last_update;
    map<ndCategoryType, ndCategory> categories;

    bool LoadLegacy(json &jdata);
};

class ndDomains
{
public:
    ndDomains();

    bool Load(void);
    nd_cat_id_t Lookup(const string &domain);

protected:
    mutex lock;
    ndCategory::index_tag index_tag;
    typedef unordered_map<nd_cat_id_t, unordered_set<string>> cat_domain_map;
    cat_domain_map domains;
    string path_domains;
};

#endif // _ND_CATEGORY_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
