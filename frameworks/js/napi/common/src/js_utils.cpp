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

#include "js_logger.h"

#ifndef MAC_PLATFORM
#include "securec.h"
#endif

namespace OHOS {
namespace PreferencesJsKit {
int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, std::string &output)
{
    size_t strBufferSize = 0;
    napi_status status = napi_get_value_string_utf8(env, jsValue, nullptr, 0, &strBufferSize);
    if (status != napi_ok) {
        LOG_ERROR("JSUtils::Convert2NativeValue get strBufferSize failed, status = %{public}d", status);
        return ERR;
    }
    if (strBufferSize > MAX_VALUE_LENGTH) {
        LOG_ERROR("JSUtils::Convert2NativeValue over maximum length.");
        return EXCEED_MAX_LENGTH;
    }
    char *str = new (std::nothrow) char[strBufferSize + 1];
    if (str == nullptr) {
        return ERR;
    }
    size_t valueSize = 0;
    status = napi_get_value_string_utf8(env, jsValue, str, strBufferSize + 1, &valueSize);
    if (status != napi_ok) {
        LOG_ERROR("JSUtils::Convert2NativeValue get jsVal failed, status = %{public}d", status);
        delete[] str;
        return ERR;
    }
    str[valueSize] = 0;
    output = std::string(str);
    delete[] str;
    return OK;
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, bool &output)
{
    bool bValue = false;
    napi_status status = napi_get_value_bool(env, jsValue, &bValue);
    if (status != napi_ok) {
        LOG_ERROR("JSUtils::Convert2NativeValue get jsVal failed, status = %{public}d", status);
        return ERR;
    }
    output = bValue;
    return OK;
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, double &output)
{
    double number = 0.0;
    napi_status status = napi_get_value_double(env, jsValue, &number);
    if (status != napi_ok) {
        LOG_ERROR("JSUtils::Convert2NativeValue get jsVal failed, status = %{public}d", status);
        return ERR;
    }
    output = number;
    return OK;
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, float &output)
{
    LOG_INFO("Convert2NativeValue js just support double data not support float");
    return napi_invalid_arg;
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, int32_t &output)
{
    LOG_INFO("Convert2NativeValue js just support double data not support int32_t");
    return napi_invalid_arg;
}

int32_t JSUtils::Convert2NativeValue(napi_env env, napi_value jsValue, int64_t &output)
{
    LOG_INFO("Convert2NativeValue js just support double data not support int64_t");
    return napi_invalid_arg;
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
        return OK;
    }
    LOG_DEBUG("Convert2Value jsValue is not null");
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
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, int64_t value)
{
    napi_value jsValue;
    if (napi_create_int64(env, value, &jsValue) != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, bool value)
{
    napi_value jsValue;
    if (napi_get_boolean(env, value, &jsValue) != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, double value)
{
    napi_value jsValue;
    if (napi_create_double(env, value, &jsValue) != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, float value)
{
    napi_value jsValue;
    if (napi_create_double(env, value, &jsValue) != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const std::string &value)
{
    napi_value jsValue;
    if (napi_create_string_utf8(env, value.c_str(), value.size(), &jsValue) != napi_ok) {
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
} // namespace PreferencesJsKit
} // namespace OHOS
