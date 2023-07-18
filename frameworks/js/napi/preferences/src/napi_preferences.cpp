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

#include <cerrno>
#include <climits>
#include <cmath>
#include <list>

#include "log_print.h"
#include "napi_async_call.h"
#include "napi_preferences_error.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_value.h"
#include "securec.h"

using namespace OHOS::NativePreferences;

namespace OHOS {
namespace PreferencesJsKit {
#define MAX_KEY_LENGTH Preferences::MAX_KEY_LENGTH
#define MAX_VALUE_LENGTH Preferences::MAX_VALUE_LENGTH

struct PreferencesAysncContext : public BaseContext {
    std::string key;
    PreferencesValue defValue = PreferencesValue(static_cast<int64_t>(0));
    napi_ref inputValueRef = nullptr;
    std::map<std::string, PreferencesValue> allElements;
    bool hasKey = false;
    std::list<std::string> keysModified;
    std::vector<std::weak_ptr<PreferencesObserver>> preferencesObservers;

    PreferencesAysncContext()
    {
    }
    virtual ~PreferencesAysncContext(){};
};

static __thread napi_ref constructor_;

PreferencesProxy::PreferencesProxy()
    : value_(nullptr), env_(nullptr), uvQueue_(nullptr)
{
}

PreferencesProxy::~PreferencesProxy()
{
    UnRegisteredAllObservers(RegisterMode::LOCAL_CHANGE);
    UnRegisteredAllObservers(RegisterMode::MULTI_PRECESS_CHANGE);
}

void PreferencesProxy::Destructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    PreferencesProxy *obj = static_cast<PreferencesProxy *>(nativeObject);
    delete obj;
}

void PreferencesProxy::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("put", SetValue),
        DECLARE_NAPI_FUNCTION("putSync", SetValueSync),
        DECLARE_NAPI_FUNCTION("get", GetValue),
        DECLARE_NAPI_FUNCTION("getSync", GetValueSync),
        DECLARE_NAPI_FUNCTION("getAll", GetAll),
        DECLARE_NAPI_FUNCTION("getAllSync", GetAllSync),
        DECLARE_NAPI_FUNCTION("delete", Delete),
        DECLARE_NAPI_FUNCTION("deleteSync", DeleteSync),
        DECLARE_NAPI_FUNCTION("clear", Clear),
        DECLARE_NAPI_FUNCTION("clearSync", ClearSync),
        DECLARE_NAPI_FUNCTION("has", HasKey),
        DECLARE_NAPI_FUNCTION("hasSync", HasKeySync),
        DECLARE_NAPI_FUNCTION("flush", Flush),
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
    obj->value_ = value;
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
    PRE_CHECK_RETURN(rc == napi_ok, context->SetError(std::make_shared<ParamTypeError>("value", "string.")));
    PRE_CHECK_RETURN(context->key.length() <= MAX_KEY_LENGTH,
        context->SetError(std::make_shared<ParamTypeError>("value", "less than 80 bytes.")));
    return OK;
}

int ParseDefValue(const napi_env &env, const napi_value &jsVal, std::shared_ptr<PreferencesAysncContext> context)
{
    int32_t rc = JSUtils::Convert2NativeValue(env, jsVal, context->defValue.value_);
    PRE_CHECK_RETURN(rc == napi_ok, context->SetError(std::make_shared<ParamTypeError>("value", "ValueType.")));
    return OK;
}

int GetAllExecute(napi_env env, std::shared_ptr<PreferencesAysncContext> context, napi_value &result)
{
    napi_create_object(env, &result);
    for (const auto &[key, value] : context->allElements) {
        napi_set_named_property(env, result, key.c_str(), JSUtils::Convert2JSValue(env, value.value_));
    }
    return OK;
}

napi_value PreferencesProxy::GetAll(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetAll start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        PRE_CHECK_PARAM_NUM_VALID(argc == 0 || argc == 1, "0 or 1");
    
        napi_unwrap(env, self, &context->boundObj);
        return OK;
    };
    auto exec = [context]() -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        context->allElements = obj->value_->GetAll();
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        return GetAllExecute(env, context, result);
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULLPTR(context, context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value PreferencesProxy::GetAllSync(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr);
    PreferencesProxy *proxy = nullptr;
    napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));

    auto context = std::make_shared<PreferencesAysncContext>();
    context->allElements = proxy->value_->GetAll();
    napi_value result = nullptr;
    GetAllExecute(env, context, result);
    return result;
}

napi_value PreferencesProxy::GetValue(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetValue start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        PRE_CHECK_PARAM_NUM_VALID(argc == 2 || argc == 3, "2 or 3");
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseKey(env, argv[0], context));
        napi_create_reference(env, argv[1], 1, &context->inputValueRef);
        napi_unwrap(env, self, &context->boundObj);
        return OK;
    };
    auto exec = [context]() -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        context->defValue = obj->value_->Get(context->key, context->defValue);
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        if (context->defValue.IsLong()) {
            LOG_DEBUG("GetValue get default value.");
            napi_get_reference_value(env, context->inputValueRef, &result);
        } else {
            result = JSUtils::Convert2JSValue(env, context->defValue.value_);
        }
        napi_delete_reference(env, context->inputValueRef);
        return OK;
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULLPTR(context, context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value PreferencesProxy::GetValueSync(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    PRE_NAPI_ASSERT(env, argc == 2, std::make_shared<ParamNumError>("2"));
    PreferencesProxy *proxy = nullptr;
    napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));

    auto context = std::make_shared<PreferencesAysncContext>();
    PRE_NAPI_ASSERT(env, ParseKey(env, argv[0], context) == OK, context->error);
    context->defValue = proxy->value_->Get(context->key, context->defValue);
    // the return back value never be an int64_t type.
    if (context->defValue.IsLong()) {
        LOG_DEBUG("GetValue get default value.");
        return argv[1];
    }
    return JSUtils::Convert2JSValue(env, context->defValue.value_);
}

napi_value PreferencesProxy::SetValue(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("SetValue start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        PRE_CHECK_PARAM_NUM_VALID(argc == 2 || argc == 3, "2 or 3");
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseKey(env, argv[0], context));
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseDefValue(env, argv[1], context));
        napi_unwrap(env, self, &context->boundObj);
        return OK;
    };
    auto exec = [context]() -> int {
        int errCode;
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        errCode = obj->value_->Put(context->key, context->defValue);
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("SetValue end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULLPTR(context, context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value PreferencesProxy::SetValueSync(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    PRE_NAPI_ASSERT(env, argc == 2, std::make_shared<ParamNumError>("2"));
    PreferencesProxy *proxy = nullptr;
    napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));

    auto context = std::make_shared<PreferencesAysncContext>();
    PRE_NAPI_ASSERT(env, ParseKey(env, argv[0], context) == OK, context->error);
    PRE_NAPI_ASSERT(env, ParseDefValue(env, argv[1], context) == OK, context->error);
    int errCode = proxy->value_->Put(context->key, context->defValue);
    PRE_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return nullptr;
}

napi_value PreferencesProxy::Delete(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Delete start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        PRE_CHECK_PARAM_NUM_VALID(argc == 1 || argc == 2, "1 or 2");
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseKey(env, argv[0], context));
        napi_unwrap(env, self, &context->boundObj);
        return OK;
    };
    auto exec = [context]() -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        int errCode = obj->value_->Delete(context->key);
        return (errCode == OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("Delete end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULLPTR(context, context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value PreferencesProxy::DeleteSync(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    PRE_NAPI_ASSERT(env, argc == 1, std::make_shared<ParamNumError>("1"));
    PreferencesProxy *proxy = nullptr;
    napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));

    auto context = std::make_shared<PreferencesAysncContext>();
    PRE_NAPI_ASSERT(env, ParseKey(env, argv[0], context) == OK, context->error);
    int errCode = proxy->value_->Delete(context->key);
    PRE_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return nullptr;
}

napi_value PreferencesProxy::HasKey(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("HasKey start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        PRE_CHECK_PARAM_NUM_VALID(argc == 1 || argc == 2, "1 or 2");
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseKey(env, argv[0], context));
        napi_unwrap(env, self, &context->boundObj);
        return OK;
    };
    auto exec = [context]() -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        context->hasKey = obj->value_->HasKey(context->key);
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_boolean(env, context->hasKey, &result);
        LOG_DEBUG("HasKey end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULLPTR(context, context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value PreferencesProxy::HasKeySync(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    PRE_NAPI_ASSERT(env, argc == 1, std::make_shared<ParamNumError>("1"));
    PreferencesProxy *proxy = nullptr;
    napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));

    auto context = std::make_shared<PreferencesAysncContext>();
    PRE_NAPI_ASSERT(env, ParseKey(env, argv[0], context) == OK, context->error);
    bool result = proxy->value_->HasKey(context->key);
    return JSUtils::Convert2JSValue(env, result);
}

napi_value PreferencesProxy::Flush(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Flush start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        PRE_CHECK_PARAM_NUM_VALID(argc == 0 || argc == 1, "0 or 1");
        napi_unwrap(env, self, &context->boundObj);
        return OK;
    };
    auto exec = [context]() -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        return obj->value_->FlushSync();
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("Flush end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULLPTR(context, context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value PreferencesProxy::Clear(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Clear start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        PRE_CHECK_PARAM_NUM_VALID(argc == 0 || argc == 1, "0 or 1");
        napi_unwrap(env, self, &context->boundObj);
        return OK;
    };
    auto exec = [context]() -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        return obj->value_->Clear();
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("Clear end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULLPTR(context, context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value PreferencesProxy::ClearSync(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr);
    PreferencesProxy *proxy = nullptr;
    napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));

    int errCode = proxy->value_->Clear();
    PRE_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return nullptr;
}

napi_value PreferencesProxy::RegisterObserver(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    const size_t requireArgc = 2;
    size_t argc = 2;
    napi_value args[2] = { 0 };

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));
    PRE_NAPI_ASSERT(env, argc == requireArgc, std::make_shared<ParamNumError>("2"));
    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, args[0], &type));
    PRE_NAPI_ASSERT(env, type == napi_string,
        std::make_shared<ParamTypeError>("registerMode", "string 'change or multiProcessChange'."));
    std::string registerMode;
    JSUtils::Convert2NativeValue(env, args[0], registerMode);
    PRE_NAPI_ASSERT(env, registerMode == STR_CHANGE || registerMode == STR_MULTI_PRECESS_CHANGE,
        std::make_shared<ParamTypeError>("registerMode", "string 'change or multiProcessChange'."));

    NAPI_CALL(env, napi_typeof(env, args[1], &type));
    PRE_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamTypeError>("callback", "function type."));

    PreferencesProxy *obj = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thiz, reinterpret_cast<void **>(&obj)));
    int errCode = obj->RegisteredObserver(args[1], ConvertToRegisterMode(registerMode));
    PRE_NAPI_ASSERT(env, errCode == OK, std::make_shared<InnerError>(errCode));

    return nullptr;
}

napi_value PreferencesProxy::UnRegisterObserver(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    const size_t requireArgc = 2;
    size_t argc = 2;
    napi_value args[2] = { 0 };

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));
    PRE_NAPI_ASSERT(env, argc > 0 && argc <= requireArgc, std::make_shared<ParamNumError>("1 or 2"));

    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, args[0], &type));
    PRE_NAPI_ASSERT(env, type == napi_string,
        std::make_shared<ParamTypeError>("registerMode", "string change or multiProcessChange."));

    std::string registerMode;
    JSUtils::Convert2NativeValue(env, args[0], registerMode);
    PRE_NAPI_ASSERT(env, registerMode == STR_CHANGE || registerMode == STR_MULTI_PRECESS_CHANGE,
        std::make_shared<ParamTypeError>("registerMode", "string change or multiProcessChange."));

    if (argc == requireArgc) {
        NAPI_CALL(env, napi_typeof(env, args[1], &type));
        PRE_NAPI_ASSERT(env, type == napi_function || type == napi_undefined || type == napi_null,
            std::make_shared<ParamTypeError>("callback", "function type."));
    }

    PreferencesProxy *obj = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thiz, reinterpret_cast<void **>(&obj)));
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
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;
    for (auto &it : observers) {
        if (JSUtils::Equals(env_, callback, it->GetCallback())) {
            LOG_INFO("The observer has already subscribed.");
            return true;
        }
    }
    return false;
}

RegisterMode PreferencesProxy::ConvertToRegisterMode(const std::string &mode)
{
    return (mode == STR_CHANGE) ? RegisterMode::LOCAL_CHANGE : RegisterMode::MULTI_PRECESS_CHANGE;
}

int PreferencesProxy::RegisteredObserver(napi_value callback, RegisterMode mode)
{
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;
    if (!HasRegisteredObserver(callback, mode)) {
        auto observer = std::make_shared<JSPreferencesObserver>(uvQueue_, callback);
        int errCode = value_->RegisterObserver(observer, mode);
        if (errCode != E_OK) {
            return errCode;
        }
        observers.push_back(observer);
    }
    LOG_INFO("The observer subscribed success.");
    return E_OK;
}

int PreferencesProxy::UnRegisteredObserver(napi_value callback, RegisterMode mode)
{
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;
    auto it = observers.begin();
    while (it != observers.end()) {
        if (JSUtils::Equals(env_, callback, (*it)->GetCallback())) {
            int errCode = value_->UnRegisterObserver(*it, mode);
            if (errCode != E_OK) {
                return errCode;
            }
            it = observers.erase(it);
            LOG_INFO("The observer unsubscribed success.");
            break; // specified observer is current iterator
        }
        ++it;
    }
    return E_OK;
}

int PreferencesProxy::UnRegisteredAllObservers(RegisterMode mode)
{
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;
    bool hasFailed = false;
    int errCode = E_OK;
    for (auto &observer : observers) {
        errCode = value_->UnRegisterObserver(observer, mode);
        if (errCode != E_OK) {
            hasFailed = true;
            LOG_ERROR("The observer unsubscribed has failed, errCode %{public}d.", errCode);
        }
    }
    observers.clear();
    return hasFailed ? E_ERROR : E_OK;
    LOG_INFO("All observers unsubscribed success.");
}
} // namespace PreferencesJsKit
} // namespace OHOS
