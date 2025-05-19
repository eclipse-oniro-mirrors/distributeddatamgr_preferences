/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "taihe_common_utils.h"

#include <algorithm>
#include <map>
#include <string>
#include <variant>
#include <vector>

#include "ani_common_utils.h"
#include "log_print.h"
namespace OHOS {
namespace PreferencesEtsKit {
namespace EtsUtils {
constexpr int32_t OFFSET_OF_SIGN = 63;
inline PreferencesValue ConvertToDouble(const ValueType_t &valueType)
{
    return static_cast<double>(valueType.get_doubleType_ref());
}

inline PreferencesValue ConvertToString(const ValueType_t &valueType)
{
    return std::string(valueType.get_stringType_ref());
}

inline PreferencesValue ConvertToBoolean(const ValueType_t &valueType)
{
    return static_cast<bool>(valueType.get_booleanType_ref());
}

inline PreferencesValue ConvertToDoubleArray(const ::taihe::array<TypesInArray_t> &valueType)
{
    std::vector<double> result;
    result.reserve(valueType.size());
    std::transform(valueType.begin(), valueType.end(), std::back_inserter(result), [](const TypesInArray_t &item) {
        return item.get_doubleType_ref();
    });
    return result;
}

inline PreferencesValue ConvertToStringArray(const ::taihe::array<TypesInArray_t> &valueType)
{
    std::vector<std::string> result;
    result.reserve(valueType.size());
    std::transform(valueType.begin(), valueType.end(), std::back_inserter(result), [](const TypesInArray_t &item) {
        return std::string(item.get_stringType_ref());
    });
    return result;
}

inline PreferencesValue ConvertToBooleanArray(const ::taihe::array<TypesInArray_t> &valueType)
{
    std::vector<bool> result;
    result.reserve(valueType.size());
    std::transform(valueType.begin(), valueType.end(), std::back_inserter(result), [](const TypesInArray_t &item) {
        return item.get_booleanType_ref();
    });
    return result;
}

PreferencesValue ConvertToArray(const ValueType_t &valueType)
{
    auto ref = valueType.get_arrayType_ref();
    if (ref.size() == 0) {
        return std::vector<double>();
    }
    auto tag = ref.at(0).get_tag();
    if (tag == TypesInArray_t::tag_t::doubleType) {
        return ConvertToDoubleArray(ref);
    } else if (tag == TypesInArray_t::tag_t::stringType) {
        return ConvertToStringArray(ref);
    } else {
        return ConvertToBooleanArray(ref);
    }
}

inline PreferencesValue ConvertToUint8Array(const ValueType_t &valueType)
{
    auto ref = valueType.get_uint8ArrayType_ref();
    return std::vector<uint8_t>(ref.begin(), ref.end());
}

int GetBigintSign(std::vector<uint64_t> &bigintArray)
{
    return (bigintArray[bigintArray.size() - 1] >> OFFSET_OF_SIGN) == 0;
}

inline PreferencesValue ConvertToBigint(const ValueType_t &valueType)
{
    auto ref = valueType.get_bigintType_ref();
    auto words = std::vector<uint64_t>(ref.begin(), ref.end());
    auto sign = GetBigintSign(words);
    return NativePreferences::BigInt(std::move(words), sign);
}

inline PreferencesValue ConvertToObject(const ValueType_t &valueType)
{
    auto ref = valueType.get_objectType_ref();
    return AniObjectToPreferencesValue(::taihe::get_env(), ref);
}

PreferencesValue ConvertToPreferencesValue(const ValueType_t &valueType)
{
    static std::map<ValueType_t::tag_t, std::function<PreferencesValue(const ValueType_t&)>> tag2FunctionMap = {
        { ValueType_t::tag_t::doubleType, ConvertToDouble },
        { ValueType_t::tag_t::stringType, ConvertToString },
        { ValueType_t::tag_t::booleanType, ConvertToBoolean },
        { ValueType_t::tag_t::arrayType, ConvertToArray },
        { ValueType_t::tag_t::uint8ArrayType, ConvertToUint8Array },
        { ValueType_t::tag_t::bigintType, ConvertToBigint },
        { ValueType_t::tag_t::objectType, ConvertToObject }
    };
    auto tag = valueType.get_tag();
    auto it = tag2FunctionMap.find(tag);
    if (it != tag2FunctionMap.end()) {
        return it->second(valueType);
    } else {
        return PreferencesValue();
    }
}

inline ValueType_t ConvertFromInt(int value)
{
    return ValueType_t::make_doubleType(static_cast<double>(value));
}

inline ValueType_t ConvertFromLong(int64_t value)
{
    return ValueType_t::make_doubleType(static_cast<double>(value));
}

inline ValueType_t ConvertFromFloat(float value)
{
    return ValueType_t::make_doubleType(static_cast<double>(value));
}

inline ValueType_t ConvertFromDouble(double value)
{
    return ValueType_t::make_doubleType(value);
}

inline ValueType_t ConvertFromString(const std::string &value)
{
    return ValueType_t::make_stringType(value);
}

inline ValueType_t ConvertFromBool(bool value)
{
    return ValueType_t::make_booleanType(value);
}

inline ValueType_t ConvertFromDoubleArray(const std::vector<double> &value)
{
    std::vector<TypesInArray_t> result;
    result.reserve(value.size());
    std::transform(value.begin(), value.end(), std::back_inserter(result), [](auto item) {
        return TypesInArray_t::make_doubleType(item);
    });
    auto arr = ::taihe::array<TypesInArray_t>(::taihe::move_data_t{}, result.data(), result.size());
    return ValueType_t::make_arrayType(std::move(arr));
}

inline ValueType_t ConvertFromStringArray(const std::vector<std::string> &value)
{
    std::vector<TypesInArray_t> result;
    result.reserve(value.size());
    std::transform(value.begin(), value.end(), std::back_inserter(result), [](auto item) {
        return TypesInArray_t::make_stringType(item);
    });
    auto arr = ::taihe::array<TypesInArray_t>(::taihe::move_data_t{}, result.data(), result.size());
    return ValueType_t::make_arrayType(std::move(arr));
}

inline ValueType_t ConvertFromBoolArray(const std::vector<bool> &value)
{
    std::vector<TypesInArray_t> result;
    result.reserve(value.size());
    std::transform(value.begin(), value.end(), std::back_inserter(result), [](auto item) {
        return TypesInArray_t::make_booleanType(item);
    });
    auto arr = ::taihe::array<TypesInArray_t>(::taihe::move_data_t{}, result.data(), result.size());
    return ValueType_t::make_arrayType(std::move(arr));
}

inline ValueType_t ConvertFromUint8Array(const std::vector<uint8_t> &value)
{
    auto arr = ::taihe::array<uint8_t>(::taihe::copy_data_t{}, value.data(), value.size());
    return ValueType_t::make_uint8ArrayType(std::move(arr));
}

inline ValueType_t ConvertFromObject(const PreferencesValue &value)
{
    ani_object obj = PreferencesValueToObject(::taihe::get_env(), value);
    return ValueType_t::make_objectType(reinterpret_cast<uintptr_t>(obj));
}

inline ValueType_t ConvertFromBigint(const BigInt &value)
{
    auto arr = ::taihe::array<uint64_t>(::taihe::copy_data_t{}, value.words_.data(), value.words_.size());
    return ValueType_t::make_bigintType(std::move(arr));
}

ValueType_t ConvertToValueType(const PreferencesValue &value)
{
    if (value.IsInt()) {
        return ConvertFromInt(value);
    }
    if (value.IsLong()) {
        return ConvertFromLong(value);
    }
    if (value.IsFloat()) {
        return ConvertFromFloat(value);
    }
    if (value.IsDouble()) {
        return ConvertFromDouble(value);
    }
    if (value.IsBool()) {
        return ConvertFromBool(value);
    }
    if (value.IsString()) {
        return ConvertFromString(value);
    }
    if (value.IsStringArray()) {
        return ConvertFromStringArray(value);
    }
    if (value.IsBoolArray()) {
        return ConvertFromBoolArray(value);
    }
    if (value.IsDoubleArray()) {
        return ConvertFromDoubleArray(value);
    }
    if (value.IsUint8Array()) {
        return ConvertFromUint8Array(value);
    }
    if (value.IsBigInt()) {
        return ConvertFromBigint(value);
    }
    return ConvertFromObject(value);
}

::taihe::map<::taihe::string, ValueType_t> ConvertMapToTaiheMap(
    const std::map<std::string, NativePreferences::PreferencesValue> &records)
{
    ::taihe::map<::taihe::string, ValueType_t> result(records.size());
    for (const auto &[key, value] : records) {
        result.emplace(key, ConvertToValueType(value));
    }
    return result;
}
} // namespace EtsUtils
} // namespace PreferencesEtsKit
} // namespace OHOS