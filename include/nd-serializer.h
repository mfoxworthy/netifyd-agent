// Netify Agent
// Copyright (C) 2015-2023 eGloo Incorporated <http://www.egloo.ca>
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

#ifndef _ND_SERIALIZER_H
#define _ND_SERIALIZER_H

class ndSerializer
{
public:
    inline void serialize(json &j, const vector<string> &keys, const json &value) const {
        if (keys.empty() || value.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }

    inline void serialize(json &j, const vector<string> &keys, const string &value) const {
        if (keys.empty() || value.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }

    inline void serialize(json &j, const vector<string> &keys, uint8_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }

    inline void serialize(json &j, const vector<string> &keys, uint16_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }

    inline void serialize(json &j, const vector<string> &keys, uint32_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }

    inline void serialize(json &j, const vector<string> &keys, uint64_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }

    inline void serialize(json &j, const vector<string> &keys, bool value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }

    inline void serialize(json &j, const vector<string> &keys, const char *value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }

    inline void serialize(json &j, const vector<string> &keys, double value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }

    inline void serialize(json &j, const vector<string> &keys, time_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }

    inline void serialize(json &j, const vector<string> &keys, const vector<nd_risk_id_t> &values) const {
        if (keys.empty() || values.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = values;
        if (keys.size() == 1)
            j[keys[0]] = values;
    }

    inline void serialize(json &j, const vector<string> &keys, const vector<unsigned> &values) const {
        if (keys.empty() || values.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = values;
        if (keys.size() == 1)
            j[keys[0]] = values;
    }

    inline void serialize(json &j, const vector<string> &keys,
        const vector<string> &values, const string &delim = "") const {
        if (keys.empty() || values.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = values;
        if (keys.size() == 1)
            j[keys[0]] = values;
    }

    inline void serialize(json &j, const vector<string> &keys, const unordered_map<string, string> &values) const {
        if (keys.empty() || values.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = values;
        if (keys.size() == 1)
            j[keys[0]] = values;
    }

    inline void serialize(vector<string> &v, const vector<string> &keys, const string &value) const {
        if (keys.empty() || value.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(value);
    }

    inline void serialize(vector<string> &v, const vector<string> &keys, uint8_t value) const {
        if (keys.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(to_string(value));
    }

    inline void serialize(vector<string> &v, const vector<string> &keys, uint16_t value) const {
        if (keys.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(to_string(value));
    }

    inline void serialize(vector<string> &v, const vector<string> &keys, uint32_t value) const {
        if (keys.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(to_string(value));
    }

    inline void serialize(vector<string> &v, const vector<string> &keys, uint64_t value) const {
        if (keys.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(to_string(value));
    }

    inline void serialize(vector<string> &v, const vector<string> &keys, bool value) const {
        if (keys.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(to_string(value));
    }

    inline void serialize(vector<string> &v, const vector<string> &keys, const char *value) const {
        if (keys.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(value);
    }

    inline void serialize(vector<string> &v, const vector<string> &keys, const vector<unsigned> &values) const {
        if (keys.empty() || values.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        string _values;
        for (auto &value : values) _values.append(_values.empty() ? to_string(value) : string(",") + to_string(value));
        v.push_back(_values);
    }

    inline void serialize(vector<string> &v, const vector<string> &keys, const vector<nd_risk_id_t> &values) const {
        if (keys.empty() || values.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        string _values;
        for (auto &value : values) _values.append(_values.empty() ? to_string(value) : string(",") + to_string(value));
        v.push_back(_values);
    }

    inline void serialize(vector<string> &v, const vector<string> &keys,
        const vector<string> &values, const string &delim = ",") const {
        if (values.empty()) return;
        if (! keys.empty()) {
            string key;
            for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
            v.push_back(key);
        }
        if (delim.empty()) {
            for (auto &i : values) v.push_back(i);
        }
        else {
            v.push_back(values.empty() ? string() :
                accumulate(
                    ++values.begin(), values.end(),
                    *values.begin(), [delim](const string &a, const string &b) { return a + delim + b; }
                )
            );
        }
    }

    inline void serialize(vector<string> &v, const vector<string> &keys, const unordered_map<string, string> &values) const {
        if (keys.empty() || values.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);

        vector<string> _values;
        for (auto &v : values) _values.push_back(v.first + ":" + v.second);
        v.push_back(_values.empty() ? string() :
            accumulate(
                ++_values.begin(), _values.end(),
                *_values.begin(), [](const string &a, const string &b) { return a + "," + b; }
            )
        );
    }
};

#endif // _ND_SERIALIZER_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
