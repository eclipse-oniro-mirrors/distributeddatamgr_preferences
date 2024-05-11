/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTEDDATAMGR_APPDATAMGR_JSUTILS_H
#define DISTRIBUTEDDATAMGR_APPDATAMGR_JSUTILS_H

#include <iostream>
#include <map>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

#include "log_print.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_preferences_error.h"
#include "preferences_value.h"

namespace OHOS {
namespace PreferencesJsKit {
namespace JSUtils {

using namespace NativePreferences;

constexpr int32_t OK = 0;
constexpr int32_t ERR = -1;
constexpr int32_t EXCEED_MAX_LENGTH = -2;
constexpr int32_t DEFAULT_BUF_SIZE = 1024;
constexpr int32_t BUF_CACHE_MARGIN = 4;
constexpr int32_t ASYNC_RST_SIZE = 2;
constexpr int32_t MAX_VALUE_LENGTH = 8 * DEFAULT_BUF_SIZE;
constexpr int32_t SYNC_RESULT_ELEMNT_NUM = 2;
constexpr const char* GLOBAL_JSON = "JSON";
constexpr const char* GLOBAL_STRINGIFY = "stringify";
constexpr const char* GLOBAL_PARSE = "parse";
constexpr const char* GLOBAL_PARSE_SENDABLE = "parseSendable";

bool Equals(napi_env env, napi_value value, napi_ref copy);

int32_t Convert2NativeValue(napi_env env, napi_value jsValue, bool &output);
int32_t Convert2NativeValue(napi_env env, napi_value jsValue, float &output);
int32_t Convert2NativeValue(napi_env env, napi_value jsValue, double &output);
int32_t Convert2NativeValue(napi_env env, napi_value jsValue, int32_t &output);
int32_t Convert2NativeValue(napi_env env, napi_value jsValue, int64_t &output);
int32_t Convert2NativeValue(napi_env env, napi_value jsValue, std::vector<uint8_t> &output);
int32_t Convert2NativeValue(napi_env env, napi_value jsValue, std::string &output);
int32_t Convert2NativeValue(napi_env env, napi_value jsValue, Object &output);
int32_t Convert2NativeValue(napi_env env, napi_value jsValue, BigInt &output);
int32_t Convert2NativeValue(napi_env env, napi_value jsValue, std::monostate &value);

template<typename T> int32_t Convert2NativeValue(napi_env env, napi_value jsValue, std::vector<T> &value);

template<typename... Types>
int32_t Convert2NativeValue(napi_env env, napi_value jsValue, std::variant<Types...> &value);

napi_value Convert2JSValue(napi_env env, int32_t value);
napi_value Convert2JSValue(napi_env env, int64_t value);
napi_value Convert2JSValue(napi_env env, uint32_t value);
napi_value Convert2JSValue(napi_env env, bool value);
napi_value Convert2JSValue(napi_env env, float value);
napi_value Convert2JSValue(napi_env env, double value);
napi_value Convert2JSValue(napi_env env, const std::vector<uint8_t> &value);
napi_value Convert2JSValue(napi_env env, const std::string &value);
napi_value Convert2JSValue(napi_env env, const OHOS::NativePreferences::Object &value);
napi_value Convert2JSValue(napi_env env, const BigInt &value);
napi_value Convert2JSValue(napi_env env, const std::monostate &value);

napi_valuetype GetValueType(napi_env env, napi_value value);
std::tuple<napi_status, napi_value> JsonStringify(napi_env env, napi_value value);
napi_value JsonParse(napi_env env, const std::string &inStr, bool sendable = false);

template<typename T>
std::enable_if_t<std::is_class_v<T>, napi_value> Convert2JSValue(napi_env env, const T &value);
template<typename T>
std::enable_if_t<!std::is_class_v<T>, napi_value> Convert2JSValue(napi_env env, T value);

template<typename T> napi_value Convert2JSValue(napi_env env, const std::vector<T> &value);

template<typename... Types> napi_value Convert2JSValue(napi_env env, const std::variant<Types...> &value);

template<typename T> int32_t GetCPPValue(napi_env env, napi_value jsValue, T &value)
{
    napi_valuetype type;
    napi_typeof(env, jsValue, &type);
    LOG_ERROR("parameter type error, jsValue type is %{public}d", type);
    return napi_invalid_arg;
}

template<typename T, typename First, typename... Types> int32_t GetCPPValue(napi_env env, napi_value jsValue, T &value)
{
    First cValue;
    auto ret = Convert2NativeValue(env, jsValue, cValue);
    if (ret != NAPI_TYPE_ERROR) {
        value = cValue;
        return ret;
    }
    return GetCPPValue<T, Types...>(env, jsValue, value);
}

template<typename T> napi_value GetJSValue(napi_env env, const T &value)
{
    return nullptr;
}

template<typename T, typename First, typename... Types> napi_value GetJSValue(napi_env env, const T &value)
{
    auto *val = std::get_if<First>(&value);
    if (val != nullptr) {
        return Convert2JSValue(env, *val);
    }
    return GetJSValue<T, Types...>(env, value);
}
} // namespace JSUtils

template<typename T> int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, std::vector<T> &value)
{
    bool isArray = false;
    napi_is_array(env, jsValue, &isArray);
    if (!isArray) {
        return NAPI_TYPE_ERROR;
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
        auto status = Convert2NativeValue(env, element, item);
        if (status != napi_ok) {
            return status;
        }
        value.push_back(std::move(item));
    }
    return napi_ok;
}

template<typename... Types>
int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, std::variant<Types...> &value)
{
    return GetCPPValue<decltype(value), Types...>(env, jsValue, value);
}

template<typename T> napi_value JSUtils::Convert2JSValue(napi_env env, const std::vector<T> &value)
{
    napi_value jsValue;
    napi_status status = napi_create_array_with_length(env, value.size(), &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }

    for (size_t i = 0; i < value.size(); ++i) {
        napi_set_element(env, jsValue, i, Convert2JSValue(env, static_cast<const T &>(value[i])));
    }
    return jsValue;
}

template<typename... Types> napi_value JSUtils::Convert2JSValue(napi_env env, const std::variant<Types...> &value)
{
    return GetJSValue<decltype(value), Types...>(env, value);
}
} // namespace PreferencesJsKit
} // namespace OHOS

#endif // DISTRIBUTEDDATAMGR_APPDATAMGR_JSUTILS_H
