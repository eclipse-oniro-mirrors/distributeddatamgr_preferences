/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "napi_preferences_helper.h"

#include "adaptor.h"

#include <string>

#include "js_ability.h"
#include "js_logger.h"
#include "js_utils.h"
#include "napi_async_proxy_v9.h"
#include "napi_preferences.h"
#include "preferences_errno.h"
#include "securec.h"

using namespace OHOS::NativePreferences;
using namespace OHOS::AppDataMgrJsKit;

namespace OHOS {
namespace PreferencesJsKit {
struct HelperAysncContext : NapiAsyncProxyV9<HelperAysncContext>::AysncContext {
    std::string path;
    std::shared_ptr<Context> context;
};

bool ParseContext(const napi_env &env, const napi_value &object, std::string &parmName, std::string &parmType,
    HelperAysncContext *asyncContext)
{
    parmName = "context";
    parmType = "StageContext or FAContext.";
    auto context = JSAbility::GetContext(env, object);
    if (context == nullptr) {
        LOG_ERROR("ParseContext get context failed.");
        return false;
    }
    asyncContext->context = context;
    return true;
}

bool ParseName(const napi_env &env, const napi_value &value, std::string &parmName, std::string &parmType,
    HelperAysncContext *asyncContext)
{
    parmName = "name";
    parmType = "no empty string.";
    LOG_DEBUG("ParseName start");
    if (asyncContext->context == nullptr) {
        LOG_ERROR("ParseName context is null.");
        return false;
    }
    std::string name = JSUtils::Convert2String(env, value);
    if (name.empty()) {
        LOG_ERROR("Get preferences name empty.");
        return false;
    }
    size_t pos = name.find_first_of('/');
    if (pos != std::string::npos) {
        parmType = "without '/' string.";
        LOG_ERROR("A name without path should be input.");
        return false;
    }
    std::string preferencesDir = asyncContext->context->GetPreferencesDir();
    asyncContext->path = preferencesDir.append("/").append(name);
    return true;
}

napi_value GetPreferences(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetPreferences start");
    NapiAsyncProxyV9<HelperAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxyV9<HelperAysncContext>::InputParser> parsers;
    parsers.push_back(ParseContext);
    parsers.push_back(ParseName);
    if (!proxy.ParseInputs(parsers)) {
        return nullptr;
    }
    return proxy.DoAsyncWork(
        "GetPreferences",
        [](HelperAysncContext *asyncContext) {
            int errCode = E_OK;
            OHOS::NativePreferences::PreferencesHelper::GetPreferences(asyncContext->path, errCode);
            LOG_DEBUG("GetPreferences return %{public}d", errCode);
            return errCode;
        },
        [](HelperAysncContext *asyncContext, napi_value &output) {
            napi_value path = nullptr;
            napi_create_string_utf8(asyncContext->env, asyncContext->path.c_str(), NAPI_AUTO_LENGTH, &path);
            auto ret = PreferencesProxy::NewInstance(asyncContext->env, path, &output);
            return (ret == napi_ok) ? OK : ERR;
        });
}

napi_value DeletePreferences(napi_env env, napi_callback_info info)
{
    NapiAsyncProxyV9<HelperAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxyV9<HelperAysncContext>::InputParser> parsers;
    parsers.push_back(ParseContext);
    parsers.push_back(ParseName);
    if (!proxy.ParseInputs(parsers)) {
        return nullptr;
    }
    return proxy.DoAsyncWork(
        "DeletePreferences",
        [](HelperAysncContext *asyncContext) {
            int errCode = PreferencesHelper::DeletePreferences(asyncContext->path);
            LOG_DEBUG("DeletePreferences execfunction return %{public}d", errCode);
            asyncContext->errorMessage = "Failed to delete preferences file";
            return (errCode == E_OK) ? OK : E_PREFERENCES_ERROR;
        },
        [](HelperAysncContext *asyncContext, napi_value &output) {
            napi_get_undefined(asyncContext->env, &output);
            LOG_DEBUG("DeletePreferences completefunction return %{public}d", E_OK);
            return OK;
        });
}

napi_value RemovePreferencesFromCache(napi_env env, napi_callback_info info)
{
    NapiAsyncProxyV9<HelperAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxyV9<HelperAysncContext>::InputParser> parsers;
    parsers.push_back(ParseContext);
    parsers.push_back(ParseName);
    if (!proxy.ParseInputs(parsers)) {
        return nullptr;
    }
    return proxy.DoAsyncWork(
        "RemovePreferencesFromCache",
        [](HelperAysncContext *asyncContext) {
            int errCode = PreferencesHelper::RemovePreferencesFromCache(asyncContext->path);
            LOG_DEBUG("RemovePreferencesFromCache return %{public}d", errCode);
            return errCode;
        },
        [](HelperAysncContext *asyncContext, napi_value &output) {
            napi_get_undefined(asyncContext->env, &output);
            return OK;
        });
}

napi_value InitPreferencesHelper(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getPreferences", GetPreferences),
        DECLARE_NAPI_FUNCTION("deletePreferences", DeletePreferences),
        DECLARE_NAPI_FUNCTION("removePreferencesFromCache", RemovePreferencesFromCache),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
}
} // namespace PreferencesJsKit
} // namespace OHOS
