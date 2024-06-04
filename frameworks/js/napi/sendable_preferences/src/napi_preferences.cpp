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

#include "napi_preferences.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cmath>
#include <list>

#include "js_sendable_utils.h"
#include "napi_async_call.h"
#include "napi_preferences_error.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_value.h"
#include "securec.h"

using namespace OHOS::NativePreferences;
using namespace OHOS::PreferencesJsKit;
namespace OHOS::Sendable::JSPreferences {
#define MAX_KEY_LENGTH Preferences::MAX_KEY_LENGTH
#define MAX_VALUE_LENGTH Preferences::MAX_VALUE_LENGTH

struct PreferencesAysncContext : public BaseContext {
    std::weak_ptr<Preferences> instance_;
    std::string key;
    PreferencesValue defValue = PreferencesValue(static_cast<int64_t>(0));
    napi_ref inputValueRef = nullptr;
    std::map<std::string, PreferencesValue> allElements;
    bool hasKey = false;
    std::vector<std::weak_ptr<PreferencesObserver>> preferencesObservers;

    PreferencesAysncContext()
    {
    }
    virtual ~PreferencesAysncContext(){};
};

static thread_local napi_ref constructor_ = nullptr;

PreferencesProxy::PreferencesProxy()
{
}

PreferencesProxy::~PreferencesProxy()
{
    std::lock_guard<decltype(mutex_)> lockGuard(mutex_);
    observers_.clear();
}

void PreferencesProxy::Destructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    PreferencesProxy *obj = static_cast<PreferencesProxy *>(nativeObject);
    delete obj;
}

void PreferencesProxy::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION_WITH_DATA("put", SetValue, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("putSync", SetValue, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("get", GetValue, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("getSync", GetValue, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("getAll", GetAll, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("getAllSync", GetAll, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("delete", Delete, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("deleteSync", Delete, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("clear", Clear, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("clearSync", Clear, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("has", HasKey, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("hasSync", HasKey, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("flush", Flush, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("flushSync", Flush, SYNC),
        DECLARE_NAPI_FUNCTION("on", RegisterObserver),
        DECLARE_NAPI_FUNCTION("off", UnregisterObserver),
    };

    napi_value cons = nullptr;
    napi_define_sendable_class(env, "Preferences", NAPI_AUTO_LENGTH, New, nullptr,
        sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors, nullptr, &cons);

    napi_create_reference(env, cons, 1, &constructor_);
}

napi_status PreferencesProxy::NewInstance(
    napi_env env, std::shared_ptr<OHOS::NativePreferences::Preferences> value, napi_value *instance)
{
    if (value == nullptr) {
        LOG_ERROR("PreferencesProxy::NewInstance get native preferences is null");
        return napi_invalid_arg;
    }
    napi_value cons;
    napi_status status = napi_get_reference_value(env, constructor_, &cons);
    if (status != napi_ok) {
        return status;
    }

    status = napi_new_instance(env, cons, 0, nullptr, instance);
    if (status != napi_ok) {
        return status;
    }

    PreferencesProxy *obj = new (std::nothrow) PreferencesProxy();
    if (obj == nullptr) {
        LOG_ERROR("PreferencesProxy::New new failed, obj is nullptr");
        return napi_invalid_arg;
    }
    obj->SetInstance(value);
    status = napi_wrap_sendable(env, *instance, obj, PreferencesProxy::Destructor, nullptr);
    if (status != napi_ok) {
        delete obj;
        return status;
    }

    return napi_ok;
}

napi_value PreferencesProxy::New(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr));
    if (thiz == nullptr) {
        LOG_WARN("get this failed");
        return nullptr;
    }
    return thiz;
}

int ParseKey(napi_env env, const napi_value arg, std::shared_ptr<PreferencesAysncContext> context)
{
    int32_t rc = Utils::ConvertFromSendable(env, arg, context->key);
    PRE_CHECK_RETURN_ERR_SET(rc == napi_ok, std::make_shared<ParamTypeError>("The key must be string."));
    PRE_CHECK_RETURN_ERR_SET(context->key.length() <= MAX_KEY_LENGTH, std::make_shared<ParamTypeError>("The key must "
                                                                                                       "be less than "
                                                                                                       "80 bytes."));
    return OK;
}

int ParseDefValue(const napi_env env, const napi_value jsVal, std::shared_ptr<PreferencesAysncContext> context)
{
    int32_t rc = Utils::ConvertFromSendable(env, jsVal, context->defValue.value_);
    PRE_CHECK_RETURN_ERR_SET(rc == napi_ok, std::make_shared<ParamTypeError>("The type of value mast be ValueType."));
    return OK;
}

std::pair<PreferencesProxy *, std::weak_ptr<Preferences>> PreferencesProxy::GetSelfInstance(
    napi_env env, napi_value self)
{
    void *boundObj = nullptr;
    napi_unwrap_sendable(env, self, &boundObj);
    if (boundObj != nullptr) {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(boundObj);
        return { obj, obj->GetInstance() };
    }
    return { nullptr, std::weak_ptr<Preferences>() };
}

int GetAllExecute(napi_env env, std::shared_ptr<PreferencesAysncContext> context, napi_value &result)
{
    std::vector<napi_property_descriptor> descriptors;
    for (const auto &[key, value] : context->allElements) {
        descriptors.push_back(napi_property_descriptor(
            DECLARE_NAPI_DEFAULT_PROPERTY(key.c_str(), Utils::ConvertToSendable(env, value.value_))));
    }
    napi_create_sendable_object_with_properties(env, descriptors.size(), descriptors.data(), &result);
    return OK;
}

napi_value PreferencesProxy::GetAll(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetAll start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 0, std::make_shared<ParamNumError>("0 or 1"));
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr, std::make_shared<InnerError>("Failed to unwrap when "
                                                                                             "getting all."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance == nullptr) {
            return E_INNER_ERROR;
        }
        context->allElements = instance->GetAll();
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) { GetAllExecute(env, context, result); };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "GetAll");
}

napi_value PreferencesProxy::GetValue(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetValue start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        PRE_CHECK_RETURN_VOID(ParseKey(env, argv[0], context) == OK);
        napi_create_reference(env, argv[1], 1, &context->inputValueRef);
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr, std::make_shared<InnerError>("Failed to unwrap when "
                                                                                             "getting value."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance == nullptr) {
            return E_INNER_ERROR;
        }
        context->defValue = instance->Get(context->key, context->defValue);
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        if (context->defValue.IsLong()) {
            LOG_DEBUG("GetValue get default value.");
            napi_get_reference_value(env, context->inputValueRef, &result);
        } else {
            result = Utils::ConvertToSendable(env, context->defValue.value_);
        }
        napi_delete_reference(env, context->inputValueRef);
        PRE_CHECK_RETURN_VOID_SET(result != nullptr, std::make_shared<InnerError>("Failed to delete reference when "
                                                                                  "getting value."));
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "GetValue");
}

napi_value PreferencesProxy::SetValue(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("SetValue start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        PRE_CHECK_RETURN_VOID(ParseKey(env, argv[0], context) == OK);
        PRE_CHECK_RETURN_VOID(ParseDefValue(env, argv[1], context) == OK);
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr, std::make_shared<InnerError>("Failed to unwrap when "
                                                                                             "setting value."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance == nullptr) {
            return E_INNER_ERROR;
        }
        return instance->Put(context->key, context->defValue);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok, std::make_shared<InnerError>("Failed to get undefined when "
                                                                                  "setting value."));
        LOG_DEBUG("SetValue end.");
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "SetValue");
}

napi_value PreferencesProxy::Delete(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Delete start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 1, std::make_shared<ParamNumError>("1 or 2"));
        PRE_CHECK_RETURN_VOID(ParseKey(env, argv[0], context) == OK);
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr, std::make_shared<InnerError>("Failed to unwrap when "
                                                                                             "deleting value."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance == nullptr) {
            return E_INNER_ERROR;
        }
        return instance->Delete(context->key);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok, std::make_shared<InnerError>("Failed to get undefined when "
                                                                                  "deleting value."));
        LOG_DEBUG("Delete end.");
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "Delete");
}

napi_value PreferencesProxy::HasKey(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("HasKey start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 1, std::make_shared<ParamNumError>("1 or 2"));
        PRE_CHECK_RETURN_VOID(ParseKey(env, argv[0], context) == OK);
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr, std::make_shared<InnerError>("Failed to unwrap when "
                                                                                             "having key."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance == nullptr) {
            return E_INNER_ERROR;
        }
        context->hasKey = instance->HasKey(context->key);
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_boolean(env, context->hasKey, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok, std::make_shared<InnerError>("Failed to get boolean when having "
                                                                                  "key."));
        LOG_DEBUG("HasKey end.");
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "HasKey");
}

napi_value PreferencesProxy::Flush(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Flush start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 0, std::make_shared<ParamNumError>("0 or 1"));
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr, std::make_shared<InnerError>("Failed to unwrap when "
                                                                                             "flushing."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance == nullptr) {
            return E_INNER_ERROR;
        }
        return instance->FlushSync();
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok, std::make_shared<InnerError>("Failed to get undefined when "
                                                                                  "flushing."));
        LOG_DEBUG("Flush end.");
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "Flush");
}

napi_value PreferencesProxy::Clear(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Clear start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 0, std::make_shared<ParamNumError>("0 or 1"));
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr, std::make_shared<InnerError>("Failed to unwrap unwrap "
                                                                                             "when clearing."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance == nullptr) {
            return E_INNER_ERROR;
        }
        return instance->Clear();
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok, std::make_shared<InnerError>("Failed to get undefined when "
                                                                                  "clearing."));
        LOG_DEBUG("Clear end.");
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "Clear");
}

napi_value PreferencesProxy::RegisterObserver(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    size_t argc = 3;            // 3 is specifies the length of the provided argc array
    napi_value args[3] = { 0 }; // 3 is the max args length

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));
    // This interface must have 2 or 3 parameters.
    PRE_NAPI_ASSERT(env, argc == 2 || argc == 3, std::make_shared<ParamNumError>("2 or 3"));
    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, args[0], &type));
    PRE_NAPI_ASSERT(env, type == napi_string, std::make_shared<ParamTypeError>("The registerMode must be string."));
    std::string registerMode;
    Utils::ConvertFromSendable(env, args[0], registerMode);
    PRE_NAPI_ASSERT(env,
        registerMode == STR_CHANGE || registerMode == STR_MULTI_PRECESS_CHANGE || registerMode == STR_DATA_CHANGE,
        std::make_shared<ParamTypeError>("The registerMode must be 'change' or 'multiProcessChange' or "
                                         "'dataChange'."));

    size_t funIndex = 1;
    std::vector<std::string> keys;
    auto mode = ConvertToRegisterMode(registerMode);
    if (mode == Observer::DATA_CHANGE) {
        int errCode = Utils::ConvertFromSendable(env, args[funIndex], keys);
        PRE_NAPI_ASSERT(env, errCode == napi_ok && !keys.empty(),
            std::make_shared<ParamTypeError>("The keys must be Array<string>."));
        funIndex++;
    }

    PRE_NAPI_ASSERT(env, argc == funIndex + 1, std::make_shared<ParamNumError>("2 or 3"));
    NAPI_CALL(env, napi_typeof(env, args[funIndex], &type));
    PRE_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamTypeError>("The callback must be function."));

    auto [obj, instance] = GetSelfInstance(env, thiz);
    PRE_NAPI_ASSERT(env, obj != nullptr && obj->GetInstance() != nullptr,
        std::make_shared<InnerError>("Failed to unwrap when register callback"));
    int errCode = obj->RegisteredObserver(env, args[funIndex], mode, keys);
    LOG_INFO("The observer subscribe %{public}d.", errCode);
    PRE_NAPI_ASSERT(env, errCode == OK, std::make_shared<InnerError>(errCode));
    return nullptr;
}

napi_value PreferencesProxy::UnregisterObserver(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    size_t argc = 3;            // 3 is specifies the length of the provided argc array
    napi_value args[3] = { 0 }; // 3 is the max args length

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));
    PRE_NAPI_ASSERT(env, argc > 0, std::make_shared<ParamNumError>("more than 1"));

    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, args[0], &type));
    PRE_NAPI_ASSERT(env, type == napi_string, std::make_shared<ParamTypeError>("The registerMode must be string."));

    std::string registerMode;
    Utils::ConvertFromSendable(env, args[0], registerMode);
    PRE_NAPI_ASSERT(env,
        registerMode == STR_CHANGE || registerMode == STR_MULTI_PRECESS_CHANGE || registerMode == STR_DATA_CHANGE,
        std::make_shared<ParamTypeError>("The unRegisterMode must be 'change' or 'multiProcessChange' or "
                                         "'dataChange'."));

    size_t funIndex = 1;
    napi_value callback = nullptr;
    std::vector<std::string> keys;
    auto mode = ConvertToRegisterMode(registerMode);
    if (mode == Observer::DATA_CHANGE) {
        int errCode = Utils::ConvertFromSendable(env, args[funIndex], keys);
        PRE_NAPI_ASSERT(env, errCode == napi_ok && !keys.empty(),
            std::make_shared<ParamTypeError>("The keys must be Array<string>."));
        funIndex++;
    }

    PRE_NAPI_ASSERT(env, argc <= funIndex + 1, std::make_shared<ParamNumError>("1 or 2 or 3"));
    if (argc == funIndex + 1) {
        NAPI_CALL(env, napi_typeof(env, args[funIndex], &type));
        PRE_NAPI_ASSERT(env, type == napi_function || type == napi_undefined || type == napi_null,
            std::make_shared<ParamTypeError>("The callback must be function."));
        callback = args[funIndex];
    }

    auto [obj, instance] = GetSelfInstance(env, thiz);
    PRE_NAPI_ASSERT(env, obj != nullptr, std::make_shared<InnerError>("Failed to unwrap when unregister callback"));

    int errCode = obj->UnregisteredObserver(env, callback, mode, keys);
    LOG_INFO("The observer unsubscribe 0x%{public}x.", errCode);
    PRE_NAPI_ASSERT(env, errCode == OK, std::make_shared<InnerError>(errCode));
    return nullptr;
}

RegisterMode PreferencesProxy::ConvertToRegisterMode(const std::string &mode)
{
    if (mode == STR_CHANGE) {
        return RegisterMode::LOCAL_CHANGE;
    } else if (mode == STR_MULTI_PRECESS_CHANGE) {
        return RegisterMode::MULTI_PRECESS_CHANGE;
    } else {
        return RegisterMode::DATA_CHANGE;
    }
}

int PreferencesProxy::RegisteredObserver(
    napi_env env, napi_value callback, RegisterMode mode, const std::vector<std::string> &keys)
{
    std::lock_guard<decltype(mutex_)> lockGuard(mutex_);
    auto it = observers_.find(env);
    if (it == observers_.end()) {
        it = observers_.emplace(
            std::piecewise_construct, std::forward_as_tuple(env), std::forward_as_tuple(env, this)).first;
    }
    if (it == observers_.end()) {
        return E_INNER_ERROR;
    }
    return it->second.Subscribe(callback, mode, keys);
}

int PreferencesProxy::UnregisteredObserver(
    napi_env env, napi_value callback, RegisterMode mode, const std::vector<std::string> &keys)
{
    std::lock_guard<decltype(mutex_)> lockGuard(mutex_);
    auto it = observers_.find(env);
    if (it == observers_.end()) {
        return E_OK;
    }
    return it->second.Unsubscribe(callback, mode, keys);
}

PreferencesProxy::JSObservers::~JSObservers()
{
    for (int mode = 0; mode < RegisterMode::CHANGE_BUTT; ++mode) {
        Unsubscribe(nullptr, RegisterMode(mode), {});
    }
    napi_remove_env_cleanup_hook(env_, &CleanEnv, this);
    uvQueue_ = nullptr;
    env_ = nullptr;
    proxy_ = nullptr;
}

PreferencesProxy::JSObservers::JSObservers(napi_env env, PreferencesProxy *proxy) : env_(env), proxy_(proxy)
{
    uvQueue_ = std::make_shared<UvQueue>(env);
    napi_add_env_cleanup_hook(env_, &CleanEnv, this);
}

void PreferencesProxy::JSObservers::CleanEnv(void *obj)
{
    auto *realObj = reinterpret_cast<JSObservers *>(obj);
    if (realObj == nullptr) {
        return;
    }
    auto proxy = realObj->proxy_;
    auto env = realObj->env_;
    if (proxy == nullptr || env == nullptr) {
        return;
    }

    std::lock_guard<decltype(proxy->mutex_)> lockGuard(proxy->mutex_);
    proxy->observers_.erase(env);
}

int PreferencesProxy::JSObservers::Subscribe(
    napi_value callback, RegisterMode mode, const std::vector<std::string> &keys)
{
    auto &observers = observers_[mode];
    auto observerIt = std::find_if(
        observers.begin(), observers.end(), [env = env_, callback](std::shared_ptr<JSObserverImpl> observer) {
            if (observer == nullptr) {
                return false;
            }
            return JSUtils::Equals(env, callback, observer->GetCallback());
        });
    if (observerIt != observers.end()) {
        return E_OK;
    }

    auto jsObserver = std::make_shared<JSObserverImpl>(uvQueue_, callback);
    auto instance = proxy_->GetInstance();
    if (instance == nullptr) {
        return E_INNER_ERROR;
    }
    auto errCode = instance->Subscribe(jsObserver, mode, keys);
    if (errCode != E_OK) {
        return errCode;
    }
    observers.push_back(jsObserver);
    return errCode;
}

int PreferencesProxy::JSObservers::Unsubscribe(
    napi_value callback, RegisterMode mode, const std::vector<std::string> &keys)
{
    auto instance = proxy_->GetInstance();
    if (instance == nullptr) {
        return E_INNER_ERROR;
    }
    int errCode = E_OK;
    auto &observers = observers_[mode];
    for (auto observer = observers.begin(); observer != observers.end();) {
        if (callback == nullptr || JSUtils::Equals(env_, callback, (*observer)->GetCallback())) {
            int status = instance->Unsubscribe(*observer, mode, keys);
            if (status == E_OK) {
                (*observer)->ClearCallback();
                observer = observers.erase(observer);
                continue;
            }
            errCode = status;
        }
        ++observer;
    }

    return errCode;
}
} // namespace OHOS::Sendable::JSPreferences
