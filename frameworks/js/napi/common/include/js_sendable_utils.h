/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_PREFERENCES_JS_COMMON_JS_SENDABLE_UTILS_H
#define OHOS_PREFERENCES_JS_COMMON_JS_SENDABLE_UTILS_H
#include <preferences_value.h>

#include <iostream>
#include <map>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "js_native_api_types.h"
#include "log_print.h"
#include "napi/native_node_api.h"
#include "napi_preferences_error.h"
#include "preferences_value.h"

namespace OHOS::Sendable::JSPreferences {
namespace Utils {
using Object = NativePreferences::Object;
using BigInt = NativePreferences::BigInt;
int32_t ConvertFromSendable(napi_env env, napi_value jsValue, bool &output);
int32_t ConvertFromSendable(napi_env env, napi_value jsValue, float &output);
int32_t ConvertFromSendable(napi_env env, napi_value jsValue, double &output);
int32_t ConvertFromSendable(napi_env env, napi_value jsValue, int32_t &output);
int32_t ConvertFromSendable(napi_env env, napi_value jsValue, int64_t &output);
int32_t ConvertFromSendable(napi_env env, napi_value jsValue, std::vector<uint8_t> &output);
int32_t ConvertFromSendable(napi_env env, napi_value jsValue, std::string &output);
int32_t ConvertFromSendable(napi_env env, napi_value jsValue, Object &output);
int32_t ConvertFromSendable(napi_env env, napi_value jsValue, BigInt &output);
int32_t ConvertFromSendable(napi_env env, napi_value jsValue, std::monostate &value);

template<typename T>
int32_t ConvertFromSendable(napi_env env, napi_value jsValue, std::vector<T> &value);

template<typename... Types>
int32_t ConvertFromSendable(napi_env env, napi_value jsValue, std::variant<Types...> &value);

napi_value ConvertToSendable(napi_env env, int32_t value);
napi_value ConvertToSendable(napi_env env, int64_t value);
napi_value ConvertToSendable(napi_env env, uint32_t value);
napi_value ConvertToSendable(napi_env env, bool value);
napi_value ConvertToSendable(napi_env env, float value);
napi_value ConvertToSendable(napi_env env, double value);
napi_value ConvertToSendable(napi_env env, const std::vector<uint8_t> &value);
napi_value ConvertToSendable(napi_env env, const std::string &value);
napi_value ConvertToSendable(napi_env env, const OHOS::NativePreferences::Object &value);
napi_value ConvertToSendable(napi_env env, const BigInt &value);
napi_value ConvertToSendable(napi_env env, const std::monostate &value);
template<typename T>
std::enable_if_t<std::is_class_v<T>, napi_value> ConvertToSendable(napi_env env, const T &value);
template<typename T>
std::enable_if_t<!std::is_class_v<T>, napi_value> ConvertToSendable(napi_env env, T value);

template<typename T>
napi_value ConvertToSendable(napi_env env, const std::vector<T> &value);

template<typename... Types>
napi_value ConvertToSendable(napi_env env, const std::variant<Types...> &value);

template<typename T>
int32_t GetCPPValue(napi_env env, napi_value jsValue, T &value)
{
    napi_valuetype type;
    napi_typeof(env, jsValue, &type);
    LOG_ERROR("parameter type error, jsValue type is %{public}d", type);
    return napi_invalid_arg;
}

template<typename T, typename First, typename... Types>
int32_t GetCPPValue(napi_env env, napi_value jsValue, T &value)
{
    First cValue;
    auto ret = ConvertFromSendable(env, jsValue, cValue);
    if (ret != PreferencesJsKit::NAPI_TYPE_ERROR) {
        value = cValue;
        return ret;
    }
    return GetCPPValue<T, Types...>(env, jsValue, value);
}

template<typename T>
napi_value GetSendableValue(napi_env env, const T &value)
{
    return nullptr;
}

template<typename T, typename First, typename... Types>
napi_value GetSendableValue(napi_env env, const T &value)
{
    auto *val = std::get_if<First>(&value);
    if (val != nullptr) {
        return ConvertToSendable(env, *val);
    }
    return GetSendableValue<T, Types...>(env, value);
}
} // namespace Utils

template<typename T>
int32_t Utils::ConvertFromSendable(napi_env env, napi_value jsValue, std::vector<T> &value)
{
    bool isArray = false;
    napi_is_array(env, jsValue, &isArray);
    if (!isArray) {
        return PreferencesJsKit::NAPI_TYPE_ERROR;
    }

    uint32_t arrLen = 0;
    napi_get_array_length(env, jsValue, &arrLen);
    if (arrLen == 0) {
        return napi_ok;
    }

    for (size_t i = 0; i < arrLen; ++i) {
        napi_value element;
        napi_get_element(env, jsValue, i, &element);
        T item;
        auto status = ConvertFromSendable(env, element, item);
        if (status != napi_ok) {
            return status;
        }
        value.push_back(std::move(item));
    }
    return napi_ok;
}

template<typename... Types>
int32_t Utils::ConvertFromSendable(napi_env env, napi_value jsValue, std::variant<Types...> &value)
{
    return GetCPPValue<decltype(value), Types...>(env, jsValue, value);
}

template<typename T>
napi_value Utils::ConvertToSendable(napi_env env, const std::vector<T> &value)
{
    napi_value jsValue;
    napi_status status = napi_create_sendable_array_with_length(env, value.size(), &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }

    for (size_t i = 0; i < value.size(); ++i) {
        napi_set_element(env, jsValue, i, ConvertToSendable(env, static_cast<const T &>(value[i])));
    }
    return jsValue;
}

template<typename... Types>
napi_value Utils::ConvertToSendable(napi_env env, const std::variant<Types...> &value)
{
    return GetSendableValue<decltype(value), Types...>(env, value);
}
} // namespace OHOS::Sendable::JSPreferences
#endif // OHOS_PREFERENCES_JS_COMMON_JS_SENDABLE_UTILS_H
