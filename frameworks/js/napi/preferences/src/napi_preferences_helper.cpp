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

#include "js_ability.h"
#include "js_utils.h"
#include "log_print.h"
#include "napi_async_call.h"
#include "napi_preferences_error.h"
#include "napi_preferences.h"
#include "preferences_errno.h"
#include "preferences.h"
#include "securec.h"

using namespace OHOS::NativePreferences;

namespace OHOS {
namespace PreferencesJsKit {
constexpr const char* DATA_GROUP_ID = "dataGroupId";
constexpr const char* NAME = "name";

struct HelperAysncContext : public BaseContext {
    std::string path;
    std::string name;
    std::string bundleName;
    std::string dataGroupId;
    std::shared_ptr<NativePreferences::Preferences> proxy;
    static constexpr uint32_t ARG_NUM = 2;

    HelperAysncContext()
    {
    }
    virtual ~HelperAysncContext(){};
};

int ParseName(const napi_env env, const napi_value name, std::shared_ptr<HelperAysncContext> context)
{
    int status = JSUtils::Convert2NativeValue(env, name, context->name);
    PRE_CHECK_RETURN_ERR_SET(status == OK && !context->name.empty(),
        std::make_shared<ParamTypeError>(NAME, "a without path non empty string."));
    size_t pos = context->name.find_first_of('/');
    PRE_CHECK_RETURN_ERR_SET(pos == std::string::npos,
        std::make_shared<ParamTypeError>(NAME, "a name string only without path."));
    return OK;
}

int ParseGroupId(const napi_env env, const napi_value dataGroupId, std::shared_ptr<HelperAysncContext> context)
{
    int res = JSUtils::Convert2NativeValue(env, dataGroupId, context->dataGroupId);
    PRE_CHECK_RETURN_ERR_SET(res == OK && !context->dataGroupId.empty(),
        std::make_shared<ParamTypeError>(DATA_GROUP_ID, "a non empty string."));
    return OK;
}

int ParseParameters(const napi_env env, napi_value* argv, std::shared_ptr<HelperAysncContext> context)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[1], &valueType);
    if (valueType == napi_string) {
        PRE_CHECK_RETURN_ERR(ParseName(env, argv[1], context) == OK);
    } else {
        napi_value nameValue = nullptr;
        napi_get_named_property(env, argv[1], NAME, &nameValue);
        PRE_CHECK_RETURN_ERR(ParseName(env, nameValue, context) == OK);
        bool hasDataGroupId = false;
        napi_has_named_property(env, argv[1], DATA_GROUP_ID, &hasDataGroupId);
        if (hasDataGroupId) {
            napi_value dataGroupIdValue = nullptr;
            napi_get_named_property(env, argv[1], DATA_GROUP_ID, &dataGroupIdValue);
            PRE_CHECK_RETURN_ERR(ParseGroupId(env, dataGroupIdValue, context) == OK);
        }
    }
    bool isStageMode = false;
    napi_status status = JSAbility::IsStageContext(env, argv[0], isStageMode);
    PRE_CHECK_RETURN_ERR_SET(status == napi_ok, std::make_shared<ParamTypeError>("context", "a Context."));

    ContextInfo contextInfo;
    int errCode = JSAbility::GetContextInfo(env, argv[0], context->dataGroupId, isStageMode, contextInfo);
    PRE_CHECK_RETURN_ERR_SET(errCode == OK, std::make_shared<InnerError>(errCode));

    context->bundleName = contextInfo.bundleName;
    context->path = contextInfo.preferencesDir.append("/").append(context->name);
    return errCode;
}

napi_value GetPreferences(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<HelperAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        PRE_CHECK_RETURN_VOID(ParseParameters(env, argv, context) == OK);
    };
    auto exec = [context]() -> int {
        int errCode = E_OK;
        Options options(context->path, context->bundleName, context->dataGroupId);
        context->proxy = PreferencesHelper::GetPreferences(options, errCode);
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        auto status = PreferencesProxy::NewInstance(env, context->proxy, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value GetPreferencesSync(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    PRE_NAPI_ASSERT(env, argc == ARG_NUM, std::make_shared<ParamNumError>("2"));

    auto context = std::make_shared<HelperAysncContext>();
    PRE_NAPI_ASSERT(env, ParseParameters(env, argv, context) == OK, context->error);

    int errCode = ERR;
    Options options(context->path, context->bundleName, context->dataGroupId);
    auto proxy = PreferencesHelper::GetPreferences(options, errCode);
    PRE_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    napi_value result;
    errCode = PreferencesProxy::NewInstance(env, proxy, &result);

    PRE_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return result;
}

napi_value DeletePreferences(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<HelperAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        PRE_CHECK_RETURN_VOID(ParseParameters(env, argv, context) == OK);
    };
    auto exec = [context]() -> int {
        return PreferencesHelper::DeletePreferences(context->path);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value DeletePreferencesSync(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    PRE_NAPI_ASSERT(env, argc == ARG_NUM, std::make_shared<ParamNumError>("2"));

    auto context = std::make_shared<HelperAysncContext>();
    PRE_NAPI_ASSERT(env, ParseParameters(env, argv, context) == OK, context->error);
    int errCode = PreferencesHelper::DeletePreferences(context->path);

    PRE_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return nullptr;
}

napi_value RemovePreferencesFromCache(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<HelperAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        PRE_CHECK_RETURN_VOID(ParseParameters(env, argv, context) == OK);
    };
    auto exec = [context]() -> int {
        return PreferencesHelper::RemovePreferencesFromCache(context->path);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RemovePreferencesFromCacheSync(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    PRE_NAPI_ASSERT(env, argc == ARG_NUM, std::make_shared<ParamNumError>("2"));

    auto context = std::make_shared<HelperAysncContext>();
    PRE_NAPI_ASSERT(env, ParseParameters(env, argv, context) == OK, context->error);
    int errCode = PreferencesHelper::RemovePreferencesFromCache(context->path);

    PRE_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return nullptr;
}

napi_value InitPreferencesHelper(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getPreferences", GetPreferences),
        DECLARE_NAPI_FUNCTION("getPreferencesSync", GetPreferencesSync),
        DECLARE_NAPI_FUNCTION("deletePreferences", DeletePreferences),
        DECLARE_NAPI_FUNCTION("deletePreferencesSync", DeletePreferencesSync),
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
