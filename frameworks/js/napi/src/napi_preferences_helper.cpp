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
#include <string>

#include "adaptor.h"
#include "async_call.h"
#include "js_ability.h"
#include "js_logger.h"
#include "js_utils.h"
#include "napi_preferences.h"
#include "napi_preferences_helper.h"
#include "preferences_errno.h"
#include "securec.h"

using namespace OHOS::NativePreferences;
using namespace OHOS::AppDataMgrJsKit;

namespace OHOS {
namespace PreferencesJsKit {
struct HelperAysncContext : public AsyncCall::Context {
    std::string path;
    std::shared_ptr<OHOS::AppDataMgrJsKit::Context> abilitycontext;

    HelperAysncContext() : Context(nullptr, nullptr)
    {
    }
    HelperAysncContext(InputAction input, OutputAction output) : Context(std::move(input), std::move(output))
    {
    }
    virtual ~HelperAysncContext(){};

    int operator()(napi_env env, size_t argc, napi_value *argv, napi_value self) override
    {
        napi_unwrap(env, self, &boundObj);
        return Context::operator()(env, argc, argv, self);
    }
    int operator()(napi_env env, napi_value &result) override
    {
        return Context::operator()(env, result);
    }
};

int ParseContext(const napi_env &env, const napi_value &object, std::shared_ptr<HelperAysncContext> context)
{
    LOG_DEBUG("ParseContext begin");
    auto abilitycontext = JSAbility::GetContext(env, object);
    PRE_SETERR_RETURN(abilitycontext != nullptr,
        context->SetError(E_PARAM_ERROR, "a Context.", "context"));
    context->abilitycontext = abilitycontext;
    LOG_DEBUG("ParseContext end");
    return OK;
}

int ParseName(const napi_env &env, const napi_value &value, std::shared_ptr<HelperAysncContext> context)
{
    LOG_DEBUG("ParseName start");
    std::string name;
    int status = JSUtils::Convert2String(env, value,name);
    PRE_SETERR_RETURN(status ==OK || !name.empty(), context->SetError(E_PARAM_ERROR, "a non empty string.", "name"));

    size_t pos = name.find_first_of('/');
    PRE_SETERR_RETURN(pos == std::string::npos, context->SetError(E_PARAM_ERROR, "a without path string.", "name"));

    std::string preferencesDir = context->abilitycontext->GetPreferencesDir();
    context->path = preferencesDir.append("/").append(name);
    return OK;
}

napi_value GetPreferences(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetPreferences start");
    auto context = std::make_shared<HelperAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        PRE_SETERR_RETURN(argc == 2 || argc == 3, context->SetError(E_PARAM_ERROR, "Parameter error. Should be 2 or 3 "
                                                                                   "parameters!"));
        PRE_CALL_RETURN(ParseContext(env, argv[0], context));
        PRE_CALL_RETURN(ParseName(env, argv[1], context));
        return OK;
    };
    auto exec = [context](AsyncCall::Context *ctx) -> int {
        int errCode = E_OK;
        OHOS::NativePreferences::PreferencesHelper::GetPreferences(context->path, errCode);
        LOG_DEBUG("GetPreferences return %{public}d", errCode);
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_value path = nullptr;
        napi_create_string_utf8(env, context->path.c_str(), NAPI_AUTO_LENGTH, &path);
        auto ret = PreferencesProxy::NewInstance(env, path, &result);
        LOG_DEBUG("GetPreferences end.");
        return (ret == napi_ok) ? OK : ERR;
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    PRE_RETURN_NULLPTR(context->errorCode == OK);
    return asyncCall.Call(env, exec);
}

napi_value DeletePreferences(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DeletePreferences start");
    auto context = std::make_shared<HelperAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        PRE_SETERR_RETURN(argc == 2 || argc == 3, context->SetError(E_PARAM_ERROR, "Parameter error. Should be 2 or 3 "
                                                                                   "parameters!"));
        PRE_CALL_RETURN(ParseContext(env, argv[0], context));
        PRE_CALL_RETURN(ParseName(env, argv[1], context));
        return OK;
    };
    auto exec = [context](AsyncCall::Context *ctx) -> int {
        int errCode = PreferencesHelper::DeletePreferences(context->path);
        LOG_DEBUG("DeletePreferences execfunction return %{public}d", errCode);
        PRE_SETERR_RETURN(errCode == E_OK, context->SetError(E_PREFERENCES_ERROR, "Failed to delete preferences "
                                                                                  "file."));

        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("DeletePreferences end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    PRE_RETURN_NULLPTR(context->errorCode == OK);
    return asyncCall.Call(env, exec);
}

napi_value RemovePreferencesFromCache(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DeletePreferences start");
    auto context = std::make_shared<HelperAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        PRE_SETERR_RETURN(argc == 2 || argc == 3, context->SetError(E_PARAM_ERROR, "Parameter error. Should be 2 or 3 "
                                                                                   "parameters!"));
        PRE_CALL_RETURN(ParseContext(env, argv[0], context));
        PRE_CALL_RETURN(ParseName(env, argv[1], context));
        return OK;
    };
    auto exec = [context](AsyncCall::Context *ctx) -> int {
        int errCode = PreferencesHelper::RemovePreferencesFromCache(context->path);
        LOG_DEBUG("RemovePreferencesFromCache return %{public}d", errCode);
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("RemovePreferencesFromCache end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    PRE_RETURN_NULLPTR(context->errorCode == OK);
    return asyncCall.Call(env, exec);
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
