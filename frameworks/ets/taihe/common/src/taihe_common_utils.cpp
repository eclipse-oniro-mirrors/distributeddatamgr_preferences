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
#include "preferences_error.h"
namespace OHOS {
namespace PreferencesEtsKit {
namespace EtsUtils {
using namespace OHOS::NativePreferences;
constexpr int32_t OFFSET_OF_SIGN = 63;
inline PreferencesValue ConvertToInt(const ValueType &valueType)
{
    return static_cast<int32_t>(valueType.get_intType_ref());
}

inline PreferencesValue ConvertToLong(const ValueType &valueType)
{
    return static_cast<int64_t>(valueType.get_longType_ref());
}

inline PreferencesValue ConvertToDouble(const ValueType &valueType)
{
    return static_cast<double>(valueType.get_doubleType_ref());
}

inline PreferencesValue ConvertToString(const ValueType &valueType)
{
    return std::string(valueType.get_stringType_ref());
}

inline PreferencesValue ConvertToBoolean(const ValueType &valueType)
{
    return static_cast<bool>(valueType.get_booleanType_ref());
}

template<typename T, typename Getter>
inline PreferencesValue ConvertToArrayWithType(const ::taihe::array<ArrayValueType> &valueType, Getter getter)
{
    std::vector<T> result;
    result.reserve(valueType.size());
    std::transform(valueType.begin(), valueType.end(), std::back_inserter(result),
        [getter](const ArrayValueType &item) {
            return getter(item);
        });
    return result;
}

PreferencesValue ConvertToArray(const ValueType &valueType)
{
    auto ref = valueType.get_arrayType_ref();
    if (ref.size() == 0) {
        return std::vector<double>();
    }
    auto tag = ref.at(0).get_tag();
    if (tag == ArrayValueType::tag_t::intType) {
        return ConvertToArrayWithType<double>(ref, [](const ArrayValueType &item) {
            return item.get_intType_ref();
        });
    } else if (tag == ArrayValueType::tag_t::longType) {
        return ConvertToArrayWithType<double>(ref, [](const ArrayValueType &item) {
            return item.get_longType_ref();
        });
    } else if (tag == ArrayValueType::tag_t::doubleType) {
        return ConvertToArrayWithType<double>(ref, [](const ArrayValueType &item) {
            return item.get_doubleType_ref();
        });
    } else if (tag == ArrayValueType::tag_t::stringType) {
        return ConvertToArrayWithType<std::string>(ref, [](const ArrayValueType &item) {
            return std::string(item.get_stringType_ref());
        });
    } else {
        return ConvertToArrayWithType<bool>(ref, [](const ArrayValueType &item) {
            return item.get_booleanType_ref();
        });
    }
}

inline PreferencesValue ConvertToUint8Array(const ValueType &valueType)
{
    auto ref = valueType.get_uint8ArrayType_ref();
    return std::vector<uint8_t>(ref.begin(), ref.end());
}

int GetBigintSign(std::vector<uint64_t> &bigintArray)
{
    return (bigintArray[bigintArray.size() - 1] >> OFFSET_OF_SIGN) == 0;
}

inline PreferencesValue ConvertToBigint(const ValueType &valueType)
{
    auto ref = valueType.get_bigintType_ref();
    auto words = std::vector<uint64_t>(ref.begin(), ref.end());
    auto sign = GetBigintSign(words);
    return NativePreferences::BigInt(std::move(words), sign);
}

inline PreferencesValue ConvertToObject(const ValueType &valueType)
{
    auto ref = valueType.get_objectType_ref();
    return AniObjectToPreferencesValue(::taihe::get_env(), ref);
}

PreferencesValue ConvertToPreferencesValue(const ValueType &valueType)
{
    static std::map<ValueType::tag_t, std::function<PreferencesValue(const ValueType&)>> tag2FunctionMap = {
        { ValueType::tag_t::intType, ConvertToInt },
        { ValueType::tag_t::longType, ConvertToLong },
        { ValueType::tag_t::doubleType, ConvertToDouble },
        { ValueType::tag_t::stringType, ConvertToString },
        { ValueType::tag_t::booleanType, ConvertToBoolean },
        { ValueType::tag_t::arrayType, ConvertToArray },
        { ValueType::tag_t::uint8ArrayType, ConvertToUint8Array },
        { ValueType::tag_t::bigintType, ConvertToBigint },
        { ValueType::tag_t::objectType, ConvertToObject }
    };
    auto tag = valueType.get_tag();
    auto it = tag2FunctionMap.find(tag);
    if (it != tag2FunctionMap.end()) {
        return it->second(valueType);
    } else {
        return PreferencesValue();
    }
}

inline ValueType ConvertFromInt(int value)
{
    return ValueType::make_intType(value);
}

inline ValueType ConvertFromLong(int64_t value)
{
    return ValueType::make_longType(value);
}

inline ValueType ConvertFromFloat(float value)
{
    return ValueType::make_doubleType(static_cast<double>(value));
}

inline ValueType ConvertFromDouble(double value)
{
    return ValueType::make_doubleType(value);
}

inline ValueType ConvertFromString(const std::string &value)
{
    return ValueType::make_stringType(value);
}

inline ValueType ConvertFromBool(bool value)
{
    return ValueType::make_booleanType(value);
}

inline ValueType ConvertFromDoubleArray(const std::vector<double> &value)
{
    std::vector<ArrayValueType> result;
    result.reserve(value.size());
    std::transform(value.begin(), value.end(), std::back_inserter(result), [](auto item) {
        return ArrayValueType::make_doubleType(item);
    });
    auto arr = ::taihe::array<ArrayValueType>(::taihe::move_data_t{}, result.data(), result.size());
    return ValueType::make_arrayType(std::move(arr));
}

inline ValueType ConvertFromStringArray(const std::vector<std::string> &value)
{
    std::vector<ArrayValueType> result;
    result.reserve(value.size());
    std::transform(value.begin(), value.end(), std::back_inserter(result), [](auto item) {
        return ArrayValueType::make_stringType(item);
    });
    auto arr = ::taihe::array<ArrayValueType>(::taihe::move_data_t{}, result.data(), result.size());
    return ValueType::make_arrayType(std::move(arr));
}

inline ValueType ConvertFromBoolArray(const std::vector<bool> &value)
{
    std::vector<ArrayValueType> result;
    result.reserve(value.size());
    std::transform(value.begin(), value.end(), std::back_inserter(result), [](auto item) {
        return ArrayValueType::make_booleanType(item);
    });
    auto arr = ::taihe::array<ArrayValueType>(::taihe::move_data_t{}, result.data(), result.size());
    return ValueType::make_arrayType(std::move(arr));
}

inline ValueType ConvertFromUint8Array(const std::vector<uint8_t> &value)
{
    auto arr = ::taihe::array<uint8_t>(::taihe::copy_data_t{}, value.data(), value.size());
    return ValueType::make_uint8ArrayType(std::move(arr));
}

inline ValueType ConvertFromObject(const PreferencesValue &value)
{
    ani_object obj = ObjectToANIObject(::taihe::get_env(), value);
    if (obj == nullptr) {
        SetBusinessError(std::make_shared<PreferencesJsKit::InnerError>("Failed to convert object."));
    }
    return ValueType::make_objectType(reinterpret_cast<uintptr_t>(obj));
}

inline ValueType ConvertFromBigint(const BigInt &value)
{
    auto arr = ::taihe::array<uint64_t>(::taihe::copy_data_t{}, value.words_.data(), value.words_.size());
    return ValueType::make_bigintType(std::move(arr));
}

ValueType ConvertToValueType(const PreferencesValue &value)
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

::taihe::map<::taihe::string, ValueType> ConvertMapToTaiheMap(
    const std::map<std::string, NativePreferences::PreferencesValue> &records)
{
    ::taihe::map<::taihe::string, ValueType> result(records.size());
    for (const auto &[key, value] : records) {
        result.emplace(key, ConvertToValueType(value));
    }
    return result;
}

void SetBusinessError(std::shared_ptr<PreferencesJsKit::JSError> error)
{
    LOG_ERROR("throw error: code=%{public}d, message=%{public}s", error->GetCode(), error->GetMsg().c_str());
    ::taihe::set_business_error(error->GetCode(), error->GetMsg().c_str());
}
} // namespace EtsUtils
} // namespace PreferencesEtsKit
} // namespace OHOS