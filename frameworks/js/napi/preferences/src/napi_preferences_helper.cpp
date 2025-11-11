/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "js_common_utils.h"
#include "napi_async_call.h"
#include "napi_preferences.h"
#include "preferences_errno.h"
#include "preferences.h"

using namespace OHOS::NativePreferences;

namespace OHOS {
namespace PreferencesJsKit {
constexpr const char* DATA_GROUP_ID = "dataGroupId";
constexpr const char* NAME = "name";
constexpr const char* STORAGE_TYPE = "storageType";

struct HelperAsyncContext : public BaseContext {
    std::string path;
    std::string name;
    std::string bundleName;
    std::string dataGroupId;
    std::shared_ptr<NativePreferences::Preferences> proxy;
    StorageType storageType = StorageType::XML;
    bool isStorageTypeSupported = false;

    HelperAsyncContext()
    {
    }
    virtual ~HelperAsyncContext(){};
};

int ParseOptionalParameters(const napi_env env, napi_value *argv, std::shared_ptr<HelperAsyncContext> context)
{
    napi_value temp = nullptr;
    bool hasGroupId = false;
    PRE_CHECK_RETURN_ERR_SET(napi_has_named_property(env, argv[1], DATA_GROUP_ID, &hasGroupId) == napi_ok,
        std::make_shared<ParamTypeError>("napi call failed when check dataGroupId."));
    if (hasGroupId) {
        PRE_CHECK_RETURN_ERR_SET(napi_get_named_property(env, argv[1], DATA_GROUP_ID, &temp) == napi_ok,
            std::make_shared<ParamTypeError>("napi call failed when get dataGroupId."));
        napi_valuetype type = napi_undefined;
        napi_status status = napi_typeof(env, temp, &type);
        if (status == napi_ok && (type != napi_null && type != napi_undefined)) {
            PRE_CHECK_RETURN_ERR_SET(JSUtils::Convert2NativeValue(env, temp, context->dataGroupId) == napi_ok,
                std::make_shared<ParamTypeError>("The dataGroupId must be string."));
        }
        PRE_CHECK_RETURN_ERR_SET(status == napi_ok,
            std::make_shared<InnerError>("parse group id: type of api failed"));
    }
    bool hasStorageType = false;
    PRE_CHECK_RETURN_ERR_SET(napi_has_named_property(env, argv[1], STORAGE_TYPE, &hasStorageType) == napi_ok,
        std::make_shared<ParamTypeError>("napi call failed when check storageType"));
    if (hasStorageType) {
        temp = nullptr;
        PRE_CHECK_RETURN_ERR_SET(napi_get_named_property(env, argv[1], STORAGE_TYPE, &temp) == napi_ok,
            std::make_shared<ParamTypeError>("napi call failed when get storageType."));
        napi_valuetype type = napi_undefined;
        napi_status status = napi_typeof(env, temp, &type);
        if (status == napi_ok && (type != napi_null && type != napi_undefined)) {
            int32_t intVal = 0;
            PRE_CHECK_RETURN_ERR_SET(napi_get_value_int32(env, temp, &intVal) == napi_ok,
                std::make_shared<ParamTypeError>("The storageType must be StorageType which is enum."));
            bool isTypeValid = (intVal == static_cast<int32_t>(StorageType::XML) ||
                intVal == static_cast<int32_t>(StorageType::GSKV));
            PRE_CHECK_RETURN_ERR_SET(isTypeValid, std::make_shared<ParamTypeError>("Storage type value invalid."));
            context->storageType = (intVal == static_cast<int32_t>(StorageType::XML)) ?
                StorageType::XML : StorageType::GSKV;
        }
        PRE_CHECK_RETURN_ERR_SET(status == napi_ok,
            std::make_shared<InnerError>("parse storage type: type of api failed"));
    }
    return OK;
}

int ParseParameters(const napi_env env, napi_value *argv, std::shared_ptr<HelperAsyncContext> context)
{
    if (JSUtils::Convert2NativeValue(env, argv[1], context->name) != napi_ok) {
        napi_value temp = nullptr;
        PRE_CHECK_RETURN_ERR_SET(napi_get_named_property(env, argv[1], NAME, &temp) == napi_ok,
            std::make_shared<ParamTypeError>("napi call failed when get name."));
        PRE_CHECK_RETURN_ERR_SET(temp && JSUtils::Convert2NativeValue(env, temp, context->name) == napi_ok,
            std::make_shared<ParamTypeError>("The name must be string."));
        PRE_CHECK_RETURN_ERR_SET(ParseOptionalParameters(env, argv, context) == OK,
            std::make_shared<ParamTypeError>("parse optional param failed"));
    }
    JSAbility::ContextInfo contextInfo;
    std::shared_ptr<JSError> err = JSAbility::GetContextInfo(env, argv[0], context->dataGroupId, contextInfo);
    PRE_CHECK_RETURN_ERR_SET(err == nullptr, err);

    context->bundleName = contextInfo.bundleName;
    context->path = contextInfo.preferencesDir.append("/").append(context->name);
    return OK;
}

napi_value GetPreferences(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<HelperAsyncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        PRE_CHECK_RETURN_VOID(ParseParameters(env, argv, context) == OK);
    };
    auto exec = [context]() -> int {
        int errCode = E_OK;
        Options options(context->path, context->bundleName, context->dataGroupId,
            context->storageType == StorageType::GSKV);
        context->proxy = PreferencesHelper::GetPreferences(options, errCode);
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        auto status = PreferencesProxy::NewInstance(env, context->proxy, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok,
            std::make_shared<InnerError>("Failed to get instance when getting preferences."));
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "PreferencesGetPreferences");
}

napi_value DeletePreferences(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<HelperAsyncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        PRE_CHECK_RETURN_VOID(ParseParameters(env, argv, context) == OK);
    };
    auto exec = [context]() -> int {
        return PreferencesHelper::DeletePreferences(context->path);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok,
            std::make_shared<InnerError>("Failed to get undefined when deleting preferences."));
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "PreferencesDeletePreferences");
}

napi_value RemovePreferencesFromCache(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<HelperAsyncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        PRE_CHECK_RETURN_VOID(ParseParameters(env, argv, context) == OK);
    };
    auto exec = [context]() -> int {
        return PreferencesHelper::RemovePreferencesFromCache(context->path);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok,
            std::make_shared<InnerError>("Failed to get undefined when removing preferences."));
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "PreferencesRemovePreferencesFromCache");
}

napi_value IsStorageTypeSupported(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<HelperAsyncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        // check param number
        PRE_NAPI_ASSERT_RETURN_VOID(env, argc == 1, std::make_shared<ParamNumError>("must have 1 param"));
        // check param data type and value
        int32_t intVal = 0;
        PRE_NAPI_ASSERT_RETURN_VOID(env, napi_get_value_int32(env, argv[0], &intVal) == napi_ok,
            std::make_shared<ParamTypeError>("The storageType must be StorageType which is enum."));
        bool isTypeValid = (intVal == static_cast<int32_t>(StorageType::XML) ||
            intVal == static_cast<int32_t>(StorageType::GSKV));
        PRE_NAPI_ASSERT_RETURN_VOID(env, isTypeValid, std::make_shared<ParamTypeError>("Storage type value invalid."));
        context->storageType = (intVal == static_cast<int32_t>(StorageType::XML)) ?
                StorageType::XML : StorageType::GSKV;
    };

    auto exec = [context]() -> int {
        context->isStorageTypeSupported = PreferencesHelper::IsStorageTypeSupported(context->storageType);
        return OK;
    };

    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_boolean(env, context->isStorageTypeSupported, &result);
        PRE_NAPI_ASSERT_RETURN_VOID(env, status == napi_ok,
            std::make_shared<InnerError>("Failed to get boolean when checking storage type"));
        LOG_DEBUG("isStorageTypeSupported end.");
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "PreferencesIsStorageTypeSupported");
}

static napi_status SetNamedProperty(napi_env env, napi_value& obj, const std::string& name, int32_t value)
{
    napi_value property = nullptr;
    napi_status status = napi_create_int32(env, value, &property);
    PRE_NAPI_ASSERT_BASE(env, status == napi_ok, std::make_shared<InnerError>("napi_create_int32 failed!"), status);

    status = napi_set_named_property(env, obj, name.c_str(), property);
    PRE_NAPI_ASSERT_BASE(env, status == napi_ok, std::make_shared<InnerError>("napi_set_named_property failed!"),
        status);
    return status;
}

static napi_value ExportStorageType(napi_env env)
{
    napi_value storageType = nullptr;
    napi_create_object(env, &storageType);
    SetNamedProperty(env, storageType, "XML", static_cast<int32_t>(StorageType::XML));
    SetNamedProperty(env, storageType, "GSKV", static_cast<int32_t>(StorageType::GSKV));
    napi_object_freeze(env, storageType);
    return storageType;
}

napi_value InitPreferencesHelper(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION_WITH_DATA("getPreferences", GetPreferences, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("getPreferencesSync", GetPreferences, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("deletePreferences", DeletePreferences, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("deletePreferencesSync", DeletePreferences, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("removePreferencesFromCache", RemovePreferencesFromCache, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("removePreferencesFromCacheSync", RemovePreferencesFromCache, SYNC),
        DECLARE_NAPI_PROPERTY("MAX_KEY_LENGTH", JSUtils::Convert2JSValue(env, Preferences::MAX_KEY_LENGTH)),
        DECLARE_NAPI_PROPERTY("MAX_VALUE_LENGTH", JSUtils::Convert2JSValue(env, Preferences::MAX_VALUE_LENGTH)),
        DECLARE_NAPI_PROPERTY("StorageType", ExportStorageType(env)),
        DECLARE_NAPI_FUNCTION_WITH_DATA("isStorageTypeSupported", IsStorageTypeSupported, SYNC),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
}
} // namespace PreferencesJsKit
} // namespace OHOS
