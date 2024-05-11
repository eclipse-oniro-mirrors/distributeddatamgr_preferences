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

#include "js_sendable_utils.h"

#include "js_utils.h"
#include "napi_preferences_error.h"
#include "node_api.h"

namespace OHOS::Sendable::JSPreferences {
using namespace PreferencesJsKit::JSUtils;
namespace Utils {

int32_t ConvertFromSendable(napi_env env, napi_value jsValue, bool &output)
{
    return Convert2NativeValue(env, jsValue, output);
}

int32_t ConvertFromSendable(napi_env env, napi_value jsValue, float &output)
{
    return Convert2NativeValue(env, jsValue, output);
}

int32_t ConvertFromSendable(napi_env env, napi_value jsValue, double &output)
{
    return Convert2NativeValue(env, jsValue, output);
}

int32_t ConvertFromSendable(napi_env env, napi_value jsValue, int32_t &output)
{
    return Convert2NativeValue(env, jsValue, output);
}

int32_t ConvertFromSendable(napi_env env, napi_value jsValue, int64_t &output)
{
    return Convert2NativeValue(env, jsValue, output);
}

int32_t ConvertFromSendable(napi_env env, napi_value jsValue, std::vector<uint8_t> &output)
{
    return Convert2NativeValue(env, jsValue, output);
}

int32_t ConvertFromSendable(napi_env env, napi_value jsValue, std::string &output)
{
    return Convert2NativeValue(env, jsValue, output);
}

int32_t ConvertFromSendable(napi_env env, napi_value jsValue, Object &output)
{
    return Convert2NativeValue(env, jsValue, output);
}

int32_t ConvertFromSendable(napi_env env, napi_value jsValue, BigInt &output)
{
    return Convert2NativeValue(env, jsValue, output);
}

int32_t ConvertFromSendable(napi_env env, napi_value jsValue, std::monostate &value)
{
    return Convert2NativeValue(env, jsValue, value);
}

napi_value ConvertToSendable(napi_env env, int32_t value)
{
    return Convert2JSValue(env, value);
}

napi_value ConvertToSendable(napi_env env, int64_t value)
{
    return Convert2JSValue(env, value);
}

napi_value ConvertToSendable(napi_env env, uint32_t value)
{
    return Convert2JSValue(env, value);
}

napi_value ConvertToSendable(napi_env env, bool value)
{
    return Convert2JSValue(env, value);
}

napi_value ConvertToSendable(napi_env env, float value)
{
    return Convert2JSValue(env, value);
}

napi_value ConvertToSendable(napi_env env, double value)
{
    return Convert2JSValue(env, value);
}

napi_value ConvertToSendable(napi_env env, const std::vector<uint8_t> &value)
{
    size_t size = value.size();
    void *data = nullptr;
    napi_value buffer = nullptr;
    napi_status ret = napi_create_sendable_arraybuffer(env, size, &data, &buffer);
    if (ret != napi_ok) {
        LOG_ERROR("napi_create_sendable_arraybuffer failed %{public}d", ret);
        return nullptr;
    }
    if (size != 0) {
        std::copy(value.begin(), value.end(), static_cast<uint8_t *>(data));
    }
    napi_value sendableValue = nullptr;
    ret = napi_create_sendable_typedarray(env, napi_uint8_array, size, buffer, 0, &sendableValue);
    if (ret != napi_ok) {
        LOG_ERROR("napi_create_sendable_typedarray failed %{public}d", ret);
        return nullptr;
    }
    return sendableValue;
}

napi_value ConvertToSendable(napi_env env, const std::string &value)
{
    return Convert2JSValue(env, value);
}

napi_value ConvertToSendable(napi_env env, const OHOS::NativePreferences::Object &value)
{
    napi_value sendableValue = JsonParse(env, value.valueStr, true);
    if (sendableValue == nullptr) {
        LOG_ERROR("Convert object failed");
    }
    return sendableValue;
}

napi_value ConvertToSendable(napi_env env, const BigInt &value)
{
    return Convert2JSValue(env, value);
}

napi_value ConvertToSendable(napi_env env, const std::monostate &value)
{
    return Convert2JSValue(env, value);
}
} // namespace Utils
} // namespace OHOS::Sendable::JSPreferences