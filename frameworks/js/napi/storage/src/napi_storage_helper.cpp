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
#include "napi_storage_helper.h"

#include <linux/limits.h>

#include <string>

#include "js_common_utils.h"
#include "napi_async_call.h"
#include "napi_storage.h"
#include "preferences.h"
#include "preferences_errno.h"

using namespace OHOS::NativePreferences;
using namespace OHOS::PreferencesJsKit;

namespace OHOS {
namespace StorageJsKit {
struct HelperAysncContext : public BaseContext {
    std::string path;
    HelperAysncContext()
    {
    }
    virtual ~HelperAysncContext(){};
};

napi_value GetStorageSync(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value args[1] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr));
    LOG_DEBUG("getPreferences %{public}zu", argc);
    napi_value instance = nullptr;
    NAPI_CALL(env, StorageProxy::NewInstance(env, args[0], &instance));
    LOG_DEBUG("getPreferences end");
    return instance;
}

int ParseString(const napi_env env, const napi_value value, std::shared_ptr<HelperAysncContext> asyncContext)
{
    if (asyncContext == nullptr) {
        LOG_WARN("error input");
        return ERR;
    }
    char *path = new (std::nothrow) char[PATH_MAX];
    if (path == nullptr) {
        LOG_ERROR("ParseString new failed, path is nullptr");
        return ERR;
    }
    size_t pathLen = 0;
    napi_get_value_string_utf8(env, value, path, PATH_MAX, &pathLen);
    asyncContext->path = path;
    delete[] path;
    return OK;
}

napi_value GetStorage(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetStorage start");
    auto context = std::make_shared<HelperAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 1, std::make_shared<ParamNumError>("1 or 2"));
        PRE_CHECK_RETURN_VOID(ParseString(env, argv[0], context) == OK);
    };
    auto exec = [context]() -> int {
        int errCode = E_OK;
        OHOS::NativePreferences::PreferencesHelper::GetPreferences(context->path, errCode);
        LOG_DEBUG("GetPreferences return %{public}d", errCode);
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_value path = nullptr;
        napi_create_string_utf8(env, context->path.c_str(), NAPI_AUTO_LENGTH, &path);
        auto ret = StorageProxy::NewInstance(env, path, &result);
        PRE_CHECK_RETURN_VOID_SET(ret == napi_ok,
            std::make_shared<InnerError>("Failed to get instance when getting storage."));
        LOG_DEBUG("GetPreferences end.");
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "GetStorage");
}

napi_status GetInputPath(napi_env env, napi_callback_info info, std::string &pathString)
{
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_status ret = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (ret != napi_ok) {
        return ret;
    }

    napi_valuetype valueType;
    ret = napi_typeof(env, args[0], &valueType);
    if (ret != napi_ok || valueType != napi_string) {
        return napi_invalid_arg;
    }

    char *path = new (std::nothrow) char[PATH_MAX];
    if (path == nullptr) {
        LOG_ERROR("GetInputPath new failed, path is nullptr");
        return napi_arraybuffer_expected;
    }
    size_t pathLen = 0;
    ret = napi_get_value_string_utf8(env, args[0], path, PATH_MAX, &pathLen);
    pathString = path;
    delete[] path;
    return ret;
}

napi_value DeleteStorageSync(napi_env env, napi_callback_info info)
{
    std::string path;
    napi_status ret = GetInputPath(env, info, path);
    if (ret != napi_ok) {
        napi_throw_error(env, nullptr, "Input path error");
        return nullptr;
    }
    int errCode = PreferencesHelper::DeletePreferences(path);
    if (errCode != E_OK) {
        LOG_ERROR("deleteStorage failed %{public}d", errCode);
        napi_throw_error(env, std::to_string(errCode).c_str(), "deleteStorage failed");
    }
    LOG_DEBUG("deleteStorage end");

    return nullptr;
}

napi_value DeleteStorage(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("DeletePreferences start");
    auto context = std::make_shared<HelperAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 1, std::make_shared<ParamNumError>("1 or 2"));
        PRE_CHECK_RETURN_VOID(ParseString(env, argv[0], context) == OK);
    };
    auto exec = [context]() -> int {
        int errCode = PreferencesHelper::DeletePreferences(context->path);
        LOG_DEBUG("DeletePreferences execfunction return %{public}d", errCode);
        PRE_CHECK_RETURN_ERR_SET(errCode == E_OK,
            std::make_shared<InnerError>("Failed to delete preferences when deleting storage."));
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok,
            std::make_shared<InnerError>("Failed to get undefined when deleting storage."));
        LOG_DEBUG("DeletePreferences end.");
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "DeleteStorage");
}

napi_value RemoveStorageFromCacheSync(napi_env env, napi_callback_info info)
{
    std::string path;
    napi_status ret = GetInputPath(env, info, path);
    if (ret != napi_ok) {
        napi_throw_error(env, nullptr, "Input path error");
        return nullptr;
    }

    int errCode = PreferencesHelper::RemovePreferencesFromCache(path);
    if (errCode != E_OK) {
        LOG_ERROR("removeStorageFromCache failed %{public}d", errCode);
        napi_throw_error(env, std::to_string(errCode).c_str(), "removeStorageFromCache failed");
    }
    LOG_DEBUG("removeStorageFromCache end");

    return nullptr;
}

napi_value RemoveStorageFromCache(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RemovePreferencesFromCache start");
    auto context = std::make_shared<HelperAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 1, std::make_shared<ParamNumError>("1 or 2"));
        PRE_CHECK_RETURN_VOID(ParseString(env, argv[0], context) == OK);
    };
    auto exec = [context]() -> int {
        int errCode = PreferencesHelper::RemovePreferencesFromCache(context->path);
        LOG_DEBUG("RemovePreferencesFromCache return %{public}d", errCode);
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok,
            std::make_shared<InnerError>("Failed to get undefined when removing storage."));
        LOG_DEBUG("RemovePreferencesFromCache end.");
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "RemoveStorageFromCache");
}

napi_value InitPreferenceHelper(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getStorage", GetStorage),
        DECLARE_NAPI_FUNCTION("getStorageSync", GetStorageSync),
        DECLARE_NAPI_FUNCTION("deleteStorage", DeleteStorage),
        DECLARE_NAPI_FUNCTION("deleteStorageSync", DeleteStorageSync),
        DECLARE_NAPI_FUNCTION("removeStorageFromCache", RemoveStorageFromCache),
        DECLARE_NAPI_FUNCTION("removeStorageFromCacheSync", RemoveStorageFromCacheSync),
        DECLARE_NAPI_PROPERTY("MAX_KEY_LENGTH", JSUtils::Convert2JSValue(env, Preferences::MAX_KEY_LENGTH)),
        DECLARE_NAPI_PROPERTY("MAX_VALUE_LENGTH", JSUtils::Convert2JSValue(env, Preferences::MAX_VALUE_LENGTH)),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
}
} // namespace StorageJsKit
} // namespace OHOS
