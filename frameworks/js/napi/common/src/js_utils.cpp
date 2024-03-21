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

#include "js_utils.h"

#ifndef MAC_PLATFORM
#include "securec.h"
#endif

using namespace OHOS::NativePreferences;

namespace OHOS {
namespace PreferencesJsKit {
int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, std::string &output)
{
    size_t bufferSize = 0;
    napi_status status = napi_get_value_string_utf8(env, jsValue, nullptr, 0, &bufferSize);
    if (status != napi_ok) {
        LOG_DEBUG("get std::string failed, status = %{public}d", status);
        return napi_invalid_arg;
    }
    if (bufferSize > MAX_VALUE_LENGTH) {
        LOG_ERROR("string  must be less than the limit length.");
        return EXCEED_MAX_LENGTH;
    }
    char *buffer = (char *)malloc(bufferSize + 1);
    if (buffer == nullptr) {
        LOG_ERROR("malloc failed, buffer is nullptr.");
        return ERR;
    }
    status = napi_get_value_string_utf8(env, jsValue, buffer, bufferSize + 1, &bufferSize);
    if (status != napi_ok) {
        free(buffer);
        LOG_DEBUG("JSUtils::Convert2NativeValue get jsVal failed, status = %{public}d", status);
        return napi_invalid_arg;
    }
    output = buffer;
    free(buffer);
    return napi_ok;
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, bool &output)
{
    bool bValue = false;
    napi_status status = napi_get_value_bool(env, jsValue, &bValue);
    if (status != napi_ok) {
        LOG_DEBUG("get bool failed, status = %{public}d", status);
        return napi_invalid_arg;
    }
    output = bValue;
    return napi_ok;
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, double &output)
{
    double number = 0.0;
    napi_status status = napi_get_value_double(env, jsValue, &number);
    if (status != napi_ok) {
        LOG_DEBUG("get double failed, status = %{public}d", status);
        return napi_invalid_arg;
    }
    output = number;
    return napi_ok;
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, float &output)
{
    LOG_DEBUG("Convert2NativeValue js just support double data not support float");
    return napi_invalid_arg;
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, int32_t &output)
{
    LOG_DEBUG("Convert2NativeValue js just support double data not support int32_t");
    return napi_invalid_arg;
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, int64_t &output)
{
    LOG_DEBUG("Convert2NativeValue js just support double data not support int64_t");
    return napi_invalid_arg;
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, std::vector<uint8_t> &output)
{
    bool isTypedarray = false;
    napi_status result = napi_is_typedarray(env, jsValue, &isTypedarray);
    if (result != napi_ok || !isTypedarray) {
        LOG_ERROR("napi_is_typedarray fail");
        return napi_invalid_arg;
    }
    napi_typedarray_type type = napi_uint8_array;
    size_t length = 0;
    void *data = nullptr;
    result = napi_get_typedarray_info(env, jsValue, &type, &length, &data, nullptr, nullptr);
    if (result != napi_ok) {
        LOG_ERROR("napi_get_typedarray_info fail");
        return napi_invalid_arg;
    }
    if (type != napi_uint8_array) {
        LOG_ERROR("value is not napi_uint8_array");
        return napi_invalid_arg;
    }
    if (length > MAX_VALUE_LENGTH) {
        LOG_ERROR("unit8Array must be less than the limit length.");
        return EXCEED_MAX_LENGTH;
    }
    output.clear();
    if (length > 0) {
        output.resize(length);
        output.assign(static_cast<uint8_t*>(data), static_cast<uint8_t*>(data) + length);
    }
    return napi_ok;
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, Object &output)
{
    bool isTypedarray = false;
    napi_status result = napi_is_typedarray(env, jsValue, &isTypedarray);
    if (result == napi_ok && isTypedarray) {
        return napi_invalid_arg;
    }
    napi_value jsonStr = JsonStringify(env, jsValue);
    if (GetValueType(env, jsonStr) != napi_string) {
        LOG_ERROR("json stringify failed");
        return napi_invalid_arg;
    }
    return Convert2NativeValue(env, jsonStr, output.valueStr);
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, std::monostate &value)
{
    napi_value tempValue;
    napi_get_null(env, &tempValue);
    bool equal = false;
    napi_strict_equals(env, jsValue, tempValue, &equal);
    if (equal) {
        return napi_ok;
    }
    napi_get_undefined(env, &tempValue);
    napi_strict_equals(env, jsValue, tempValue, &equal);
    if (equal) {
        return napi_ok;
    }
    LOG_DEBUG("std::monostate is not null");
    return napi_invalid_arg;
}

bool JSUtils::Equals(napi_env env, napi_value value, napi_ref copy)
{
    if (copy == nullptr) {
        return (value == nullptr);
    }

    napi_value copyValue = nullptr;
    napi_get_reference_value(env, copy, &copyValue);

    bool isEquals = false;
    napi_strict_equals(env, value, copyValue, &isEquals);
    return isEquals;
}

napi_value JSUtils::Convert2JSValue(napi_env env, int32_t value)
{
    napi_value jsValue;
    if (napi_create_int32(env, value, &jsValue) != napi_ok) {
        LOG_DEBUG("Convert int32_t failed");
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, uint32_t value)
{
    napi_value jsValue;
    if (napi_create_uint32(env, value, &jsValue) != napi_ok) {
        LOG_DEBUG("Convert uint32_t failed");
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, int64_t value)
{
    napi_value jsValue;
    if (napi_create_int64(env, value, &jsValue) != napi_ok) {
        LOG_DEBUG("Convert int64_t failed");
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, bool value)
{
    napi_value jsValue;
    if (napi_get_boolean(env, value, &jsValue) != napi_ok) {
        LOG_DEBUG("Convert bool failed");
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, double value)
{
    napi_value jsValue;
    if (napi_create_double(env, value, &jsValue) != napi_ok) {
        LOG_DEBUG("Convert double failed");
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, float value)
{
    napi_value jsValue;
    if (napi_create_double(env, value, &jsValue) != napi_ok) {
        LOG_DEBUG("Convert float failed");
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const std::vector<uint8_t> &value)
{
    size_t size = value.size();
    void *data = nullptr;
    napi_value buffer = nullptr;
    napi_status ret = napi_create_arraybuffer(env, size, &data, &buffer);
    if (ret != napi_ok) {
        LOG_ERROR("napi_create_arraybuffer failed %{public}d", ret);
        return nullptr;
    }
    if (size != 0) {
        std::copy(value.begin(), value.end(), static_cast<uint8_t*>(data));
    }
    napi_value napiValue = nullptr;
    ret = napi_create_typedarray(env, napi_uint8_array, size, buffer, 0, &napiValue);
    if (ret != napi_ok) {
        LOG_ERROR("napi_create_typedarray failed %{public}d", ret);
        return nullptr;
    }
    return napiValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const Object &value)
{
    napi_value jsValue = JsonParse(env, value.valueStr);
    if (GetValueType(env, jsValue) != napi_object) {
        LOG_ERROR("Convert object failed");
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const std::string &value)
{
    napi_value jsValue = nullptr;
    if (napi_create_string_utf8(env, value.c_str(), value.size(), &jsValue) != napi_ok) {
        LOG_DEBUG("Convert std::string failed");
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const std::monostate &value)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

napi_valuetype JSUtils::GetValueType(napi_env env, napi_value value)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    return valueType;
}

napi_value JSUtils::JsonStringify(napi_env env, napi_value value)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    if (GetValueType(env, value) != napi_object) {
        LOG_DEBUG("Not of object type");
        return undefined;
    }
    napi_value global = nullptr;
    PRE_CHECK_RETURN_CORE(napi_get_global(env, &global) == napi_ok, PRE_REVT_NOTHING, undefined);
    napi_value json = nullptr;
    PRE_CHECK_RETURN_CORE(napi_get_named_property(env, global, GLOBAL_JSON, &json) == napi_ok,
        PRE_REVT_NOTHING, undefined);
    napi_value stringify = nullptr;
    PRE_CHECK_RETURN_CORE(napi_get_named_property(env, json, GLOBAL_STRINGIFY, &stringify) == napi_ok,
        PRE_REVT_NOTHING, undefined);
    if (GetValueType(env, stringify) != napi_function) {
        LOG_ERROR("Get stringify func failed");
        return undefined;
    }
    napi_value res = nullptr;
    napi_value argv[1] = {value};
    PRE_CHECK_RETURN_CORE(napi_call_function(env, json, stringify, 1, argv, &res) == napi_ok,
        PRE_REVT_NOTHING, undefined);
    return res;
}

napi_value JSUtils::JsonParse(napi_env env, const std::string &inStr)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    if (inStr.empty()) {
        LOG_ERROR("JsonParse failed, inStr is empty");
        return undefined;
    }
    napi_value jsValue = Convert2JSValue(env, inStr);
    napi_value global = nullptr;
    PRE_CHECK_RETURN_CORE(napi_get_global(env, &global) == napi_ok, PRE_REVT_NOTHING, undefined);
    napi_value json = nullptr;
    PRE_CHECK_RETURN_CORE(napi_get_named_property(env, global, GLOBAL_JSON, &json) == napi_ok,
        PRE_REVT_NOTHING, undefined);
    napi_value parse = nullptr;
    PRE_CHECK_RETURN_CORE(napi_get_named_property(env, json, GLOBAL_PARSE, &parse) == napi_ok,
        PRE_REVT_NOTHING, undefined);
    if (GetValueType(env, parse) != napi_function) {
        LOG_ERROR("Get parse func failed");
        return undefined;
    }
    napi_value res = undefined;
    napi_value argv[1] = {jsValue};
    PRE_CHECK_RETURN_CORE(napi_call_function(env, json, parse, 1, argv, &res) == napi_ok, PRE_REVT_NOTHING, undefined);
    return res;
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, std::vector<std::string> &output)
{
    uint32_t arrLen = 0;
    napi_get_array_length(env, jsValue, &arrLen);
    if (arrLen == 0) {
        return napi_invalid_arg;
    }
    std::vector<std::string> result;
    for (size_t i = 0; i < arrLen; ++i) {
        napi_value element;
        if (napi_get_element(env, jsValue, i, &element) != napi_ok) {
            return napi_invalid_arg;
        }
        std::string resValue;
        if (Convert2NativeValue(env, element, resValue) != napi_ok) {
            return napi_invalid_arg;
        }
        result.push_back(resValue);
    }
    output = result;
    return napi_ok;
}
} // namespace PreferencesJsKit
} // namespace OHOS
