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

#include <string>

#include "napi_async_call.h"
#include "js_ability.h"
#include "js_logger.h"
#include "js_utils.h"
#include "napi_preferences.h"
#include "napi_preferences_error.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "securec.h"

using namespace OHOS::NativePreferences;

namespace OHOS {
namespace PreferencesJsKit {
struct HelperAysncContext : public BaseContext {
    std::string path;
    std::shared_ptr<OHOS::PreferencesJsKit::Context> abilitycontext;
    std::shared_ptr<Preferences> proxy;
    
    HelperAysncContext()
    {
    }
    virtual ~HelperAysncContext(){};
};

int ParseContext(const napi_env &env, const napi_value &object, std::shared_ptr<HelperAysncContext> context)
{
    LOG_DEBUG("ParseContext begin");
    auto abilitycontext = JSAbility::GetContext(env, object);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("context", "a Context.");
    PRE_CHECK_RETURN_CALL_RESULT(abilitycontext != nullptr, context->SetError(paramError));
    context->abilitycontext = abilitycontext;
    LOG_DEBUG("ParseContext end");
    return OK;
}

int ParseName(const napi_env &env, const napi_value &value, std::shared_ptr<HelperAysncContext> context)
{
    LOG_DEBUG("ParseName start");
    std::string name;
    int status = JSUtils::Convert2String(env, value, name);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("name", "a without path non empty string.");
    PRE_CHECK_RETURN_CALL_RESULT(status == OK || !name.empty(), context->SetError(paramError));

    size_t pos = name.find_first_of('/');
    PRE_CHECK_RETURN_CALL_RESULT(pos == std::string::npos, context->SetError(paramError));

    std::string preferencesDir = context->abilitycontext->GetPreferencesDir();
    context->path = preferencesDir.append("/").append(name);
    return OK;
}

napi_value GetPreferences(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetPreferences start");
    auto context = std::make_shared<HelperAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseContext(env, argv[0], context));
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseName(env, argv[1], context));
        return OK;
    };
    auto exec = [context]() -> int {
        int errCode = E_OK;
        context->proxy = OHOS::NativePreferences::PreferencesHelper::GetPreferences(context->path, errCode);
        LOG_DEBUG("GetPreferences return %{public}d", errCode);
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_value path = nullptr;
        napi_create_string_utf8(env, context->path.c_str(), NAPI_AUTO_LENGTH, &path);
        auto ret = PreferencesProxy::NewInstance(env, context->proxy, &result);
        LOG_DEBUG("GetPreferences end.");
        return (ret == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULLPTR(context, context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value DeletePreferences(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DeletePreferences start");
    auto context = std::make_shared<HelperAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseContext(env, argv[0], context));
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseName(env, argv[1], context));
        return OK;
    };
    auto exec = [context]() -> int {
        int errCode = PreferencesHelper::DeletePreferences(context->path);
        LOG_DEBUG("DeletePreferences execfunction return %{public}d", errCode);
        std::shared_ptr<Error> deleteError = std::make_shared<DeleteError>();
        PRE_CHECK_RETURN_CALL_RESULT(errCode == E_OK, context->SetError(deleteError));

        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("DeletePreferences end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULLPTR(context, context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RemovePreferencesFromCache(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DeletePreferences start");
    auto context = std::make_shared<HelperAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseContext(env, argv[0], context));
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseName(env, argv[1], context));
        return OK;
    };
    auto exec = [context]() -> int {
        int errCode = PreferencesHelper::RemovePreferencesFromCache(context->path);
        LOG_DEBUG("RemovePreferencesFromCache return %{public}d", errCode);
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("RemovePreferencesFromCache end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULLPTR(context, context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value InitPreferencesHelper(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getPreferences", GetPreferences),
        DECLARE_NAPI_FUNCTION("deletePreferences", DeletePreferences),
        DECLARE_NAPI_FUNCTION("removePreferencesFromCache", RemovePreferencesFromCache),
        DECLARE_NAPI_PROPERTY("MAX_KEY_LENGTH", JSUtils::Convert2JSValue(env, Preferences::MAX_KEY_LENGTH)),
        DECLARE_NAPI_PROPERTY("MAX_VALUE_LENGTH", JSUtils::Convert2JSValue(env, Preferences::MAX_VALUE_LENGTH)),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
}
} // namespace PreferencesJsKit
} // namespace OHOS
