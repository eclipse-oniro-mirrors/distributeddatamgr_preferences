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
    std::shared_ptr<OHOS::PreferencesJsKit::Context> abilityContext;
    std::shared_ptr<Preferences> proxy;
    
    HelperAysncContext()
    {
    }
    virtual ~HelperAysncContext(){};
};

int ParseContext(const napi_env &env, const napi_value &object, std::shared_ptr<HelperAysncContext> context)
{
    LOG_DEBUG("ParseContext begin");
    auto abilityContext = JSAbility::GetContext(env, object);
    PRE_CHECK_RETURN(abilityContext != nullptr,
        context->SetError(std::make_shared<ParamTypeError>("context", "a Context.")));
    context->abilityContext = abilityContext;
    LOG_DEBUG("ParseContext end");
    return OK;
}

int ParseName(const napi_env &env, const napi_value &value, std::shared_ptr<HelperAysncContext> context)
{
    LOG_DEBUG("ParseName start");
    std::string name;
    int status = JSUtils::Convert2NativeValue(env, value, name);
    PRE_CHECK_RETURN(status == OK || !name.empty(),
        context->SetError(std::make_shared<ParamTypeError>("name", "a without path non empty string.")));

    size_t pos = name.find_first_of('/');
    PRE_CHECK_RETURN(pos == std::string::npos,
        context->SetError(std::make_shared<ParamTypeError>("name", "a name string only without path.")));

    std::string preferencesDir = context->abilityContext->GetPreferencesDir();
    context->path = preferencesDir.append("/").append(name);
    return OK;
}

napi_value GetPreferences(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetPreferences start");
    auto context = std::make_shared<HelperAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        PRE_CHECK_PARAM_NUM_VALID(argc == 2 || argc == 3, "2 or 3");
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
        PRE_CHECK_PARAM_NUM_VALID(argc == 2 || argc == 3, "2 or 3");
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseContext(env, argv[0], context));
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseName(env, argv[1], context));
        return OK;
    };
    auto exec = [context]() -> int {
        int errCode = PreferencesHelper::DeletePreferences(context->path);
        LOG_DEBUG("DeletePreferences execfunction return %{public}d", errCode);
        PRE_CHECK_RETURN(errCode == E_OK, context->SetError(std::make_shared<DeleteError>()));

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
        PRE_CHECK_PARAM_NUM_VALID(argc == 2 || argc == 3, "2 or 3");
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

napi_value RemovePreferencesFromCacheSync(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    PRE_NAPI_ASSERT(env, argc == 2, std::make_shared<ParamNumError>("2"));
    PreferencesProxy *proxy = nullptr;
    napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));

    auto context = std::make_shared<HelperAysncContext>();
    PRE_NAPI_ASSERT(env, ParseContext(env, argv[0], context) == OK, context->error);
    PRE_NAPI_ASSERT(env, ParseName(env, argv[1], context) == OK, context->error);
    int errCode = PreferencesHelper::RemovePreferencesFromCache(context->path);

    PRE_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return nullptr;
}

napi_value InitPreferencesHelper(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getPreferences", GetPreferences),
        DECLARE_NAPI_FUNCTION("deletePreferences", DeletePreferences),
        DECLARE_NAPI_FUNCTION("removePreferencesFromCache", RemovePreferencesFromCache),
        DECLARE_NAPI_FUNCTION("removePreferencesFromCacheSync", RemovePreferencesFromCacheSync),
        DECLARE_NAPI_PROPERTY("MAX_KEY_LENGTH", JSUtils::Convert2JSValue(env, Preferences::MAX_KEY_LENGTH)),
        DECLARE_NAPI_PROPERTY("MAX_VALUE_LENGTH", JSUtils::Convert2JSValue(env, Preferences::MAX_VALUE_LENGTH)),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
}
} // namespace PreferencesJsKit
} // namespace OHOS
