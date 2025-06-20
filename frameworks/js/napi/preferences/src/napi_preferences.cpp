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
#include <cctype>
#include <cerrno>
#include <climits>
#include <cmath>
#include <list>

#include "napi_async_call.h"
#include "preferences_error.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_value.h"

using namespace OHOS::NativePreferences;

namespace OHOS {
namespace PreferencesJsKit {
#define MAX_KEY_LENGTH Preferences::MAX_KEY_LENGTH
#define MAX_VALUE_LENGTH Preferences::MAX_VALUE_LENGTH

struct PreferencesAysncContext : public BaseContext {
    std::weak_ptr<Preferences> instance_;
    std::string key;
    PreferencesValue defValue = PreferencesValue(static_cast<int64_t>(0));
    napi_ref inputValueRef = nullptr;
    std::unordered_map<std::string, PreferencesValue> allElements;
    bool hasKey = false;
    std::vector<std::weak_ptr<PreferencesObserver>> preferencesObservers;

    PreferencesAysncContext()
    {
    }
    virtual ~PreferencesAysncContext(){};
};

static __thread napi_ref constructor_;

PreferencesProxy::PreferencesProxy()
    : env_(nullptr), uvQueue_(nullptr)
{
}

PreferencesProxy::~PreferencesProxy()
{
    UnRegisteredAllObservers(RegisterMode::LOCAL_CHANGE);
    UnRegisteredAllObservers(RegisterMode::MULTI_PRECESS_CHANGE);
    UnRegisteredAllObservers(RegisterMode::DATA_CHANGE);
    SetInstance(nullptr);
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
        DECLARE_NAPI_FUNCTION("off", UnRegisterObserver),
    };

    napi_value cons = nullptr;
    napi_define_class(env, "Preferences", NAPI_AUTO_LENGTH, New, nullptr,
        sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors, &cons);

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
    obj->env_ = env;
    obj->uvQueue_ = std::make_shared<UvQueue>(env);
    status = napi_wrap(env, *instance, obj, PreferencesProxy::Destructor, nullptr, nullptr);
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
    int32_t rc = JSUtils::Convert2NativeValue(env, arg, context->key);
    PRE_CHECK_RETURN_ERR_SET(rc == napi_ok, std::make_shared<ParamTypeError>("The key must be string."));
    PRE_CHECK_RETURN_ERR_SET(context->key.length() <= MAX_KEY_LENGTH,
        std::make_shared<ParamTypeError>("The key must be less than 1024 bytes."));
    return OK;
}

int ParseDefValue(const napi_env env, const napi_value jsVal, std::shared_ptr<PreferencesAysncContext> context)
{
    int32_t rc = JSUtils::Convert2NativeValue(env, jsVal, context->defValue.value_);
    if (rc == EXCEED_MAX_LENGTH) {
        PRE_CHECK_RETURN_ERR_SET(rc == napi_ok,
            std::make_shared<ParamTypeError>("The type of value must be less then 16 * 1024 * 1024 btyes."));
    }
    PRE_CHECK_RETURN_ERR_SET(rc == napi_ok, std::make_shared<ParamTypeError>("The type of value must be ValueType."));
    return OK;
}

bool IsPureDigits(const std::string& str)
{
    return std::all_of(str.begin(), str.end(), ::isdigit);
}

int GetAllExecute(napi_env env, std::shared_ptr<PreferencesAysncContext> context, napi_value &result)
{
    std::vector<napi_property_descriptor> descriptors;
    descriptors.reserve(context->allElements.size());
    bool containsPureDigits = false;
    for (const auto &[key, value] : context->allElements) {
        if (!containsPureDigits) {
            if (IsPureDigits(key)) {
                containsPureDigits = true;
            }
        }
        descriptors.push_back(napi_property_descriptor(
            DECLARE_NAPI_DEFAULT_PROPERTY(key.c_str(), JSUtils::Convert2JSValue(env, value.value_))));
    }
    if (containsPureDigits) {
        napi_create_object(env, &result);
        napi_define_properties(env, result, descriptors.size(), descriptors.data());
    } else {
        napi_create_object_with_properties(env, &result, descriptors.size(), descriptors.data());
    }
    return OK;
}

std::pair<PreferencesProxy *, std::weak_ptr<Preferences>> PreferencesProxy::GetSelfInstance(
    napi_env env, napi_value self)
{
    void *boundObj = nullptr;
    napi_unwrap(env, self, &boundObj);
    if (boundObj != nullptr) {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(boundObj);
        return { obj, obj->GetInstance() };
    }
    return { nullptr, std::weak_ptr<Preferences>() };
}

napi_value PreferencesProxy::GetAll(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 0, std::make_shared<ParamNumError>("0 or 1"));
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr && context->instance_.lock() != nullptr,
            std::make_shared<InnerError>("Failed to unwrap when getting all."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance == nullptr) {
            LOG_ERROR("Failed to get instance when GetAll, The instance is nullptr.");
            return E_INNER_ERROR;
        }
        context->allElements = instance->GetAllDatas();
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        GetAllExecute(env, context, result);
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "PreferencesGetAll");
}

napi_value PreferencesProxy::GetValue(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        PRE_CHECK_RETURN_VOID(ParseKey(env, argv[0], context) == OK);
        napi_create_reference(env, argv[1], 1, &context->inputValueRef);
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr && context->instance_.lock() != nullptr,
            std::make_shared<InnerError>("Failed to unwrap when getting value."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance == nullptr) {
            LOG_ERROR("Failed to get instance when GetValue, The instance is nullptr.");
            return E_INNER_ERROR;
        }
        context->defValue = instance->Get(context->key, context->defValue);
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        if (context->defValue.IsLong()) {
            napi_get_reference_value(env, context->inputValueRef, &result);
        } else {
            result = JSUtils::Convert2JSValue(env, context->defValue.value_);
        }
        napi_delete_reference(env, context->inputValueRef);
        PRE_CHECK_RETURN_VOID_SET(result != nullptr,
            std::make_shared<InnerError>("Failed to delete reference when getting value."));
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "PreferencesGetValue");
}

napi_value PreferencesProxy::SetValue(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        PRE_CHECK_RETURN_VOID(ParseKey(env, argv[0], context) == OK);
        PRE_CHECK_RETURN_VOID(ParseDefValue(env, argv[1], context) == OK);
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr && context->instance_.lock() != nullptr,
            std::make_shared<InnerError>("Failed to unwrap when setting value."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance == nullptr) {
            LOG_ERROR("Failed to get instance when SetValue, The instance is nullptr.");
            return E_INNER_ERROR;
        }
        return instance->Put(context->key, context->defValue);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok,
            std::make_shared<InnerError>("Failed to get undefined when setting value."));
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "PreferencesSetValue");
}

napi_value PreferencesProxy::Delete(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 1, std::make_shared<ParamNumError>("1 or 2"));
        PRE_CHECK_RETURN_VOID(ParseKey(env, argv[0], context) == OK);
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr && context->instance_.lock() != nullptr,
            std::make_shared<InnerError>("Failed to unwrap when deleting value."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance != nullptr) {
            return instance->Delete(context->key);
        }
        LOG_ERROR("Failed to get instance when Delete, The instance is nullptr.");
        return E_INNER_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok,
            std::make_shared<InnerError>("Failed to get undefined when deleting value."));
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "PreferencesDelete");
}

napi_value PreferencesProxy::HasKey(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 1, std::make_shared<ParamNumError>("1 or 2"));
        PRE_CHECK_RETURN_VOID(ParseKey(env, argv[0], context) == OK);
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr && context->instance_.lock() != nullptr,
            std::make_shared<InnerError>("Failed to unwrap when having key."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance == nullptr) {
            LOG_ERROR("Failed to get instance when HasKey, The instance is nullptr.");
            return E_INNER_ERROR;
        }
        context->hasKey = instance->HasKey(context->key);
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_boolean(env, context->hasKey, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok,
            std::make_shared<InnerError>("Failed to get boolean when having key."));
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "PreferencesHasKey");
}

napi_value PreferencesProxy::Flush(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 0, std::make_shared<ParamNumError>("0 or 1"));
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr && context->instance_.lock() != nullptr,
            std::make_shared<InnerError>("Failed to unwrap when flushing."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance == nullptr) {
            LOG_ERROR("Failed to get instance when Flush, The instance is nullptr.");
            return E_INNER_ERROR;
        }
        return instance->FlushSync();
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok,
            std::make_shared<InnerError>("Failed to get undefined when flushing."));
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "PreferencesFlush");
}

napi_value PreferencesProxy::Clear(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        PRE_CHECK_RETURN_VOID_SET(argc == 0, std::make_shared<ParamNumError>("0 or 1"));
        std::tie(context->boundObj, context->instance_) = GetSelfInstance(env, self);
        PRE_CHECK_RETURN_VOID_SET(context->boundObj != nullptr && context->instance_.lock() != nullptr,
            std::make_shared<InnerError>("Failed to unwrap unwrap when clearing."));
    };
    auto exec = [context]() -> int {
        auto instance = context->instance_.lock();
        if (instance != nullptr) {
            return instance->Clear();
        }
        LOG_ERROR("Failed to get instance when Clear, The instance is nullptr.");
        return E_INNER_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        PRE_CHECK_RETURN_VOID_SET(status == napi_ok,
            std::make_shared<InnerError>("Failed to get undefined when clearing."));
    };
    context->SetAction(env, info, input, exec, output);

    PRE_CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context, "PreferencesClear");
}

napi_value PreferencesProxy::RegisterObserver(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    size_t argc = 3; // 3 is specifies the length of the provided argc array
    napi_value args[3] = { 0 }; // 3 is the max args length

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));
    // This interface must have 2 or 3 parameters.
    PRE_NAPI_ASSERT(env, argc == 2 || argc == 3, std::make_shared<ParamNumError>("2 or 3"));
    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, args[0], &type));
    PRE_NAPI_ASSERT(env, type == napi_string,
        std::make_shared<ParamTypeError>("The registerMode must be string."));
    std::string registerMode;
    JSUtils::Convert2NativeValue(env, args[0], registerMode);
    PRE_NAPI_ASSERT(env, registerMode == STR_CHANGE || registerMode == STR_MULTI_PRECESS_CHANGE
        || registerMode == STR_DATA_CHANGE, std::make_shared<ParamTypeError>(
        "The registerMode must be 'change' or 'multiProcessChange' or 'dataChange'."));

    if (registerMode == STR_DATA_CHANGE) {
        return RegisterDataObserver(env, argc, args, thiz);
    }

    // This interface must have 2 parameters.
    PRE_NAPI_ASSERT(env, argc == 2, std::make_shared<ParamNumError>("2"));
    NAPI_CALL(env, napi_typeof(env, args[1], &type));
    PRE_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamTypeError>("The callback must be function."));

    auto [obj, instance] = GetSelfInstance(env, thiz);
    PRE_NAPI_ASSERT(env, obj != nullptr && instance.lock() != nullptr,
        std::make_shared<InnerError>("Failed to unwrap when register callback"));
    int errCode = obj->RegisteredObserver(args[1], ConvertToRegisterMode(registerMode));
    PRE_NAPI_ASSERT(env, errCode == OK, std::make_shared<InnerError>(errCode));

    return nullptr;
}

napi_value PreferencesProxy::UnRegisterObserver(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    size_t argc = 3; // 3 is specifies the length of the provided argc array
    napi_value args[3] = { 0 }; // 3 is the max args length

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));
    PRE_NAPI_ASSERT(env, argc > 0, std::make_shared<ParamNumError>("more than 1"));

    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, args[0], &type));
    PRE_NAPI_ASSERT(env, type == napi_string,
        std::make_shared<ParamTypeError>("The registerMode must be string."));

    std::string registerMode;
    JSUtils::Convert2NativeValue(env, args[0], registerMode);
    PRE_NAPI_ASSERT(env, registerMode == STR_CHANGE || registerMode == STR_MULTI_PRECESS_CHANGE
        || registerMode == STR_DATA_CHANGE, std::make_shared<ParamTypeError>(
        "The unRegisterMode must be 'change' or 'multiProcessChange' or 'dataChange'."));

    if (registerMode == STR_DATA_CHANGE) {
        return UnRegisterDataObserver(env, argc, args, thiz);
    }

    // This interface must less than 2 parameters.
    PRE_NAPI_ASSERT(env, argc <= 2, std::make_shared<ParamNumError>("1 or 2"));
    // when there are 2 parameters, function needs to be parsed.
    if (argc == 2) {
        NAPI_CALL(env, napi_typeof(env, args[1], &type));
        PRE_NAPI_ASSERT(env, type == napi_function || type == napi_undefined || type == napi_null,
            std::make_shared<ParamTypeError>("The callback must be function."));
    }

    auto [obj, instance] = GetSelfInstance(env, thiz);
    PRE_NAPI_ASSERT(env, obj != nullptr && instance.lock() != nullptr,
        std::make_shared<InnerError>("Failed to unwrap when register callback"));
    int errCode;
    if (type == napi_function) {
        errCode = obj->UnRegisteredObserver(args[1], ConvertToRegisterMode(registerMode));
    } else {
        errCode = obj->UnRegisteredAllObservers(ConvertToRegisterMode(registerMode));
    }
    PRE_NAPI_ASSERT(env, errCode == OK, std::make_shared<InnerError>(errCode));
    return nullptr;
}

bool PreferencesProxy::HasRegisteredObserver(napi_value callback, RegisterMode mode)
{
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ :
        (mode == RegisterMode::MULTI_PRECESS_CHANGE) ? multiProcessObservers_ : dataObservers_;
    for (auto &it : observers) {
        if (JSUtils::Equals(env_, callback, it->GetCallback())) {
            LOG_DEBUG("The observer has already subscribed.");
            return true;
        }
    }
    return false;
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

int PreferencesProxy::RegisteredObserver(napi_value callback, RegisterMode mode)
{
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;
    if (!HasRegisteredObserver(callback, mode)) {
        auto observer = std::make_shared<JSPreferencesObserver>(uvQueue_, callback);
        auto instance = GetInstance();
        if (instance == nullptr) {
            LOG_ERROR("The observer subscribed failed.");
            return E_INNER_ERROR;
        }
        int errCode = instance->RegisterObserver(observer, mode);
        if (errCode != E_OK) {
            return errCode;
        }
        observers.push_back(observer);
    }
    LOG_DEBUG("The observer subscribed success.");
    return E_OK;
}

int PreferencesProxy::UnRegisteredObserver(napi_value callback, RegisterMode mode)
{
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;
    auto instance = GetInstance();
    if (instance == nullptr) {
        LOG_ERROR("The observer unsubscribed failed.");
        return E_INNER_ERROR;
    }
    auto it = observers.begin();
    while (it != observers.end()) {
        if (JSUtils::Equals(env_, callback, (*it)->GetCallback())) {
            int errCode = instance->UnRegisterObserver(*it, mode);
            if (errCode != E_OK) {
                return errCode;
            }
            (*it)->ClearCallback();
            it = observers.erase(it);
            LOG_DEBUG("The observer unsubscribed success.");
            break; // specified observer is current iterator
        }
        ++it;
    }
    return E_OK;
}

int PreferencesProxy::UnRegisteredAllObservers(RegisterMode mode, const std::vector<std::string> &keys)
{
    if (mode == RegisterMode::DATA_CHANGE) {
        return UnRegisteredDataObserver(keys, nullptr);
    }
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;
    bool hasFailed = false;
    int errCode = E_OK;
    auto instance = GetInstance();
    if (instance == nullptr) {
        LOG_ERROR("All observer unsubscribed failed.");
        return E_INNER_ERROR;
    }
    for (auto &observer : observers) {
        errCode = instance->UnRegisterObserver(observer, mode);
        if (errCode != E_OK) {
            hasFailed = true;
            LOG_ERROR("The observer unsubscribed has failed, errCode %{public}d.", errCode);
        }
        observer->ClearCallback();
    }
    observers.clear();
    LOG_DEBUG("All observers unsubscribed success.");
    return hasFailed ? E_ERROR : E_OK;
}

napi_value PreferencesProxy::RegisterDataObserver(napi_env env, size_t argc, napi_value *argv, napi_value self)
{
    const size_t funcIndex = 2; // 2 is the index of the callback function
    // This interface must have 3 parameters.
    PRE_NAPI_ASSERT(env, argc == 3, std::make_shared<ParamNumError>("3"));
    bool isArray = false;
    NAPI_CALL(env, napi_is_array(env, argv[1], &isArray));
    PRE_NAPI_ASSERT(env, isArray == true,
        std::make_shared<ParamTypeError>("The keys must be Array."));

    std::vector<std::string> keys;
    int errCode = JSUtils::Convert2NativeValue(env, argv[1], keys);
    PRE_NAPI_ASSERT(env, errCode == napi_ok && !keys.empty(),
        std::make_shared<ParamTypeError>("The keys must be Array<string>."));

    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, argv[funcIndex], &type));
    PRE_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamTypeError>("The callback must be function."));

    auto [obj, instance] = GetSelfInstance(env, self);
    PRE_NAPI_ASSERT(env, obj != nullptr && instance.lock() != nullptr,
        std::make_shared<InnerError>("Failed to unwrap when register callback"));
    errCode = obj->RegisteredDataObserver(keys, argv[funcIndex]);
    PRE_NAPI_ASSERT(env, errCode == OK, std::make_shared<InnerError>(errCode));
    return nullptr;
}

int PreferencesProxy::RegisteredDataObserver(const std::vector<std::string> &keys, napi_value callback)
{
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = dataObservers_;
    auto instance = GetInstance();
    if (instance == nullptr) {
        LOG_ERROR("The dataChange observer subscribed failed.");
        return E_INNER_ERROR;
    }
    if (!HasRegisteredObserver(callback, RegisterMode::DATA_CHANGE)) {
        auto observer = std::make_shared<JSPreferencesObserver>(uvQueue_, callback);
        int errCode = instance->RegisterDataObserver(observer, keys);
        if (errCode != E_OK) {
            LOG_ERROR("Registered dataObserver failed:%{public}d", errCode);
            return errCode;
        }
        observers.push_back(observer);
    }
    LOG_DEBUG("The dataChange observer subscribed success.");
    return E_OK;
}

napi_value PreferencesProxy::UnRegisterDataObserver(napi_env env, size_t argc, napi_value *argv, napi_value self)
{
    const size_t funcIndex = 2; // 2 is the index of the callback function
    // This interface should have 2 or 3 parameters.
    PRE_NAPI_ASSERT(env, argc > 1 && argc <= 3, std::make_shared<ParamNumError>("2 or 3"));

    std::vector<std::string> keys;
    int errCode = JSUtils::Convert2NativeValue(env, argv[1], keys);
    PRE_NAPI_ASSERT(env, errCode == napi_ok,
        std::make_shared<ParamTypeError>("The keys must be Array<string>."));

    napi_valuetype type = napi_undefined;
    // when there are 3 parameters, function needs to be parsed.
    if (argc == 3) {
        NAPI_CALL(env, napi_typeof(env, argv[funcIndex], &type));
        PRE_NAPI_ASSERT(env, type == napi_function || type == napi_undefined || type == napi_null,
            std::make_shared<ParamTypeError>("The callback must be function."));
    }
    auto [obj, instance] = GetSelfInstance(env, self);
    PRE_NAPI_ASSERT(env, obj != nullptr && instance.lock() != nullptr,
        std::make_shared<InnerError>("Failed to unwrap when unregister callback"));
    if (type == napi_function) {
        errCode = obj->UnRegisteredDataObserver(keys, argv[funcIndex]);
    } else {
        errCode = obj->UnRegisteredAllObservers(RegisterMode::DATA_CHANGE, keys);
    }
    PRE_NAPI_ASSERT(env, errCode == OK, std::make_shared<InnerError>(errCode));
    return nullptr;
}

int PreferencesProxy::UnRegisteredDataObserver(const std::vector<std::string> &keys, napi_value callback)
{
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = dataObservers_;
    bool isUnRegisterAll = (callback == nullptr);
    auto instance = GetInstance();
    if (instance == nullptr) {
        LOG_ERROR("The dataChange observer unsubscribed failed.");
        return E_INNER_ERROR;
    }
    auto it = observers.begin();
    while (it != observers.end()) {
        if (isUnRegisterAll || JSUtils::Equals(env_, callback, (*it)->GetCallback())) {
            int errCode = instance->UnRegisterDataObserver(*it, keys);
            if (errCode != E_OK && errCode != E_OBSERVER_RESERVE) {
                return errCode;
            } else if (errCode == E_OK) {
                (*it)->ClearCallback();
                it = observers.erase(it);
            } else {
                ++it;
            }
            if (!isUnRegisterAll) {
                break;
            }
        } else {
            ++it;
        }
    }
    LOG_DEBUG("The dataChange observer unsubscribed success.");
    return E_OK;
}
} // namespace PreferencesJsKit
} // namespace OHOS