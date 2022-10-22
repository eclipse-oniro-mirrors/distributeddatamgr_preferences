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
#include "securec.h"

namespace OHOS {
namespace AppDataMgrJsKit {
std::string JSUtils::Convert2String(napi_env env, napi_value jsStr, bool useDefaultBufSize)
{
    size_t str_buffer_size = 0;
    napi_get_value_string_utf8(env, jsStr, nullptr, 0, &str_buffer_size);
    str_buffer_size = (useDefaultBufSize && (str_buffer_size > DEFAULT_BUF_SIZE))
                          ? (DEFAULT_BUF_SIZE + BUF_CACHE_MARGIN)
                          : (str_buffer_size + BUF_CACHE_MARGIN);
    char *buf = new char[str_buffer_size + 1];
    size_t len = 0;
    napi_get_value_string_utf8(env, jsStr, buf, str_buffer_size, &len);
    buf[len] = 0;
    std::string value(buf);
    delete[] buf;
    return value;
}

int32_t JSUtils::Convert2String(napi_env env, napi_value jsStr, std::string &output)
{
    char *str = new char[MAX_VALUE_LENGTH + 1];
    size_t valueSize = 0;
    napi_status status = napi_get_value_string_utf8(env, jsStr, str, MAX_VALUE_LENGTH, &valueSize);
    if (status != napi_ok) {
        LOG_ERROR("JSUtils::Convert2String get jsVal failed, status = %{public}d", status);
        delete[] str;
        return ERR;
    }
    output = std::string(str);
    delete[] str;
    return OK;
}

int32_t JSUtils::Convert2Bool(napi_env env, napi_value jsBool, bool &output)
{
    bool bValue = false;
    napi_status status = napi_get_value_bool(env, jsBool, &bValue);
    if (status != napi_ok) {
        LOG_ERROR("JSUtils::Convert2Bool get jsVal failed, status = %{public}d", status);
        return ERR;
    }
    output = bValue;
    return OK;
}

int32_t JSUtils::Convert2Double(napi_env env, napi_value jsNum, double &output)
{
    double number = 0.0;
    napi_status status = napi_get_value_double(env, jsNum, &number);
    if (status != napi_ok) {
        LOG_ERROR("JSUtils::Convert2Double get jsVal failed, status = %{public}d", status);
        return ERR;
    }
    output = number;
    return OK;
}

int32_t JSUtils::Convert2StrVector(napi_env env, napi_value value, std::vector<std::string> &output)
{
    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, value, &arrLen);
    if (status != napi_ok) {
        LOG_ERROR("JSUtils::Convert2StrVector get arrLength failed, status = %{public}d", status);
        output = {};
        return ERR;
    }
    napi_value element = nullptr;
    for (size_t i = 0; i < arrLen; ++i) {
        status = napi_get_element(env, value, i, &element);
        if (status != napi_ok) {
            LOG_ERROR("JSUtils::Convert2StrVector get element failed, status = %{public}d", status);
            return ERR;
        }
        std::string str;
        if (Convert2String(env, element, str) != OK) {
            LOG_ERROR("JSUtils::Convert2StrVector convert element failed");
            return ERR;
        }
        output.push_back(str);
    }
    return OK;
}

int32_t JSUtils::Convert2BoolVector(napi_env env, napi_value value, std::vector<bool> &output)
{
    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, value, &arrLen);
    if (status != napi_ok) {
        LOG_ERROR("JSUtils::Convert2BoolVector get arrLength failed, status = %{public}d", status);
        output = {};
        return ERR;
    }
    napi_value element = nullptr;
    for (size_t i = 0; i < arrLen; ++i) {
        status = napi_get_element(env, value, i, &element);
        if (status != napi_ok) {
            LOG_ERROR("JSUtils::Convert2BoolVector get element failed, status = %{public}d", status);
            return ERR;
        }
        bool bVal = false;
        if (Convert2Bool(env, element, bVal) != OK) {
            LOG_ERROR("JSUtils::Convert2BoolVector convert element failed");
            return ERR;
        }
        output.push_back(bVal);
    }
    return OK;
}

int32_t JSUtils::Convert2DoubleVector(napi_env env, napi_value value, std::vector<double> &output)
{
    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, value, &arrLen);
    if (status != napi_ok) {
        LOG_ERROR("JSUtils::Convert2DoubleVector get arrLength failed, status = %{public}d", status);
        output = {};
        return ERR;
    }
    napi_value element = nullptr;
    for (size_t i = 0; i < arrLen; ++i) {
        status = napi_get_element(env, value, i, &element);
        if (status != napi_ok) {
            LOG_ERROR("JSUtils::Convert2DoubleVector get element failed, status = %{public}d", status);
            return ERR;
        }
        double number = 0.0;
        if (Convert2Double(env, element, number) != OK) {
            LOG_ERROR("JSUtils::Convert2Double convert element failed");
            return ERR;
        }
        output.push_back(number);
    }
    return OK;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const std::vector<std::string> &value)
{
    napi_value jsValue;
    napi_status status = napi_create_array_with_length(env, value.size(), &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }

    for (size_t i = 0; i < value.size(); ++i) {
        napi_set_element(env, jsValue, i, Convert2JSValue(env, value[i]));
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const std::string &value)
{
    napi_value jsValue;
    napi_status status = napi_create_string_utf8(env, value.c_str(), value.size(), &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const std::vector<uint8_t> &value)
{
    napi_value jsValue;
    void *native = nullptr;
    napi_value buffer = nullptr;
    napi_status status = napi_create_arraybuffer(env, value.size(), &native, &buffer);
    if (status != napi_ok) {
        return nullptr;
    }
    int result = memcpy_s(native, value.size(), value.data(), value.size());
    if (result != EOK && value.size() > 0) {
        return nullptr;
    }
    status = napi_create_typedarray(env, napi_uint8_array, value.size(), buffer, 0, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, int32_t value)
{
    napi_value jsValue;
    napi_status status = napi_create_int32(env, value, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, int64_t value)
{
    napi_value jsValue;
    napi_status status = napi_create_int64(env, value, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, double value)
{
    napi_value jsValue;
    napi_status status = napi_create_double(env, value, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, bool value)
{
    napi_value jsValue;
    napi_status status = napi_get_boolean(env, value, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const std::map<std::string, int> &value)
{
    napi_value jsValue;
    napi_status status = napi_create_array_with_length(env, value.size(), &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }

    int index = 0;
    for (const auto &[device, result] : value) {
        napi_value jsElement;
        status = napi_create_array_with_length(env, SYNC_RESULT_ELEMNT_NUM, &jsElement);
        if (status != napi_ok) {
            return nullptr;
        }
        napi_set_element(env, jsElement, 0, Convert2JSValue(env, device));
        napi_set_element(env, jsElement, 1, Convert2JSValue(env, result));
        napi_set_element(env, jsValue, index++, jsElement);
    }

    return jsValue;
}

int32_t JSUtils::Convert2JSValue(napi_env env, std::string value, napi_value &output)
{
    std::string tempStr = std::string(value);
    if (napi_create_string_utf8(env, tempStr.c_str(), tempStr.size(), &output) != napi_ok) {
        LOG_ERROR("Convert2JSValue create JS string failed");
        return ERR;
    }
    return OK;
}

int32_t JSUtils::Convert2JSValue(napi_env env, bool value, napi_value &output)
{
    if (napi_get_boolean(env, value, &output) != napi_ok) {
        LOG_ERROR("Convert2JSValue create JS bool failed");
        return ERR;
    }
    return OK;
}

int32_t JSUtils::Convert2JSValue(napi_env env, double value, napi_value &output)
{
    if (napi_create_double(env, value, &output) != napi_ok) {
        LOG_ERROR("Convert2JSValue create JS double failed");
        return ERR;
    }
    return OK;
}

int32_t JSUtils::Convert2JSDoubleArr(napi_env env, std::vector<double> value, napi_value &output)
{
    size_t arrLen = value.size();
    napi_status status = napi_create_array_with_length(env, arrLen, &output);
    if (status != napi_ok) {
        LOG_ERROR("JSUtils::Convert2JSValue get arrLength failed");
        return ERR;
    }
    napi_value val = nullptr;
    for (size_t i = 0; i < arrLen; i++) {
        if (Convert2JSValue(env, value[i], val) != OK) {
            LOG_ERROR("JSUtils::Convert2JSValue creat double failed");
            return ERR;
        }
        status = napi_set_element(env, output, i, val);
        if (status != napi_ok) {
            LOG_ERROR("JSUtils::Convert2JSValue set element failed");
            return ERR;
        }
    }
    return OK;
}

int32_t JSUtils::Convert2JSBoolArr(napi_env env, std::vector<bool> value, napi_value &output)
{
    size_t arrLen = value.size();
    napi_status status = napi_create_array_with_length(env, arrLen, &output);
    if (status != napi_ok) {
        LOG_ERROR("JSUtils::Convert2JSValue get arrLength failed");
        return ERR;
    }
    for (size_t i = 0; i < arrLen; i++) {
        napi_value val = nullptr;
        if (Convert2JSValue(env, value[i], val) != OK) {
            LOG_ERROR("JSUtils::Convert2JSValue creat bool failed");
            return ERR;
        }
        status = napi_set_element(env, output, i, val);
        if (status != napi_ok) {
            LOG_ERROR("JSUtils::Convert2JSValue set element failed");
            return ERR;
        }
    }
    return OK;
}

int32_t JSUtils::Convert2JSStringArr(napi_env env, std::vector<std::string> value, napi_value &output)
{
    size_t arrLen = value.size();
    napi_status status = napi_create_array_with_length(env, arrLen, &output);
    if (status != napi_ok) {
        LOG_ERROR("JSUtils::Convert2JSValue get arrLength failed");
        return ERR;
    }
    for (size_t i = 0; i < arrLen; i++) {
        napi_value val = nullptr;
        if (Convert2JSValue(env, value[i], val) != OK) {
            LOG_ERROR("JSUtils::Convert2JSValue creat string failed");
            return ERR;
        }
        status = napi_set_element(env, output, i, val);
        if (status != napi_ok) {
            LOG_ERROR("JSUtils::Convert2JSValue set element failed");
            return ERR;
        }
    }
    return OK;
}
} // namespace AppDataMgrJsKit
} // namespace OHOS
