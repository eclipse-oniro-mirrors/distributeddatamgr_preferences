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

#include "napi_async_call.h"
#include "js_logger.h"
#include "js_utils.h"
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
    PreferencesValue defValue = PreferencesValue(static_cast<int>(0));
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
    for (auto &observer : dataObserver_) {
        value_->UnRegisterObserver(observer);
    }
    dataObserver_.clear();
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
        DECLARE_NAPI_FUNCTION("get", GetValue),
        DECLARE_NAPI_FUNCTION("getAll", GetAll),
        DECLARE_NAPI_FUNCTION("delete", Delete),
        DECLARE_NAPI_FUNCTION("clear", Clear),
        DECLARE_NAPI_FUNCTION("has", HasKey),
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
    PreferencesProxy *proxy = nullptr;
    status = napi_unwrap(env, *instance, reinterpret_cast<void **>(&proxy));
    if (proxy == nullptr || status != napi_ok) {
        LOG_ERROR("PreferencesProxy::NewInstance unwarp native preferences is null");
        return napi_generic_failure;
    }
    proxy->value_ = std::move(value);
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
    PreferencesProxy *obj = new (std::nothrow) PreferencesProxy();
    if (obj == nullptr) {
        LOG_ERROR("PreferencesProxy::New new failed, obj is nullptr");
        return nullptr;
    }
    obj->env_ = env;
    obj->uvQueue_ = std::make_shared<UvQueue>(env);
    napi_status status = napi_wrap(env, thiz, obj, PreferencesProxy::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        delete obj;
        return nullptr;
    }
    return thiz;
}

int ParseKey(const napi_env &env, const napi_value &arg, std::shared_ptr<PreferencesAysncContext> context)
{
    // get input key
    char key[MAX_KEY_LENGTH] = { 0 };
    size_t keySize = 0;
    napi_status status = napi_get_value_string_utf8(env, arg, key, MAX_KEY_LENGTH, &keySize);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("key", "a non empty string.");
    PRE_CHECK_RETURN_CALL_RESULT(status == napi_ok, context->SetError(paramError));

    context->key = key;
    return OK;
}

int32_t ParseDoubleElement(
    const napi_env &env, const napi_value &jsVal, std::shared_ptr<PreferencesAysncContext> context)
{
    std::vector<double> array;
    if (JSUtils::Convert2DoubleVector(env, jsVal, array) != E_OK) {
        LOG_ERROR("ParseDoubleElement Convert2DoubleVector failed");
        return E_ERROR;
    }
    context->defValue = array;
    return E_OK;
}

int32_t ParseBoolElement(const napi_env &env, const napi_value &jsVal, std::shared_ptr<PreferencesAysncContext> context)
{
    std::vector<bool> array;
    if (JSUtils::Convert2BoolVector(env, jsVal, array) != E_OK) {
        LOG_ERROR("ParseBoolElement Convert2BoolVector failed");
        return E_ERROR;
    }
    context->defValue = array;
    return E_OK;
}

int32_t ParseStringElement(
    const napi_env &env, const napi_value &jsVal, std::shared_ptr<PreferencesAysncContext> context)
{
    std::vector<std::string> array;
    if (JSUtils::Convert2StrVector(env, jsVal, array) != E_OK) {
        LOG_ERROR("ParseStringElement Convert2StrVector failed");
        return E_ERROR;
    }
    context->defValue = array;
    return E_OK;
}

int32_t ParseObjectElement(napi_valuetype valueType, const napi_env &env, const napi_value &jsVal,
    std::shared_ptr<PreferencesAysncContext> context)
{
    if (valueType == napi_number) {
        return ParseDoubleElement(env, jsVal, context);
    } else if (valueType == napi_boolean) {
        return ParseBoolElement(env, jsVal, context);
    } else if (valueType == napi_string) {
        return ParseStringElement(env, jsVal, context);
    } else {
        LOG_ERROR("ParseObjectElement unexpected valueType");
        return E_ERROR;
    }
}

int32_t ParseDefObject(const napi_env &env, const napi_value &jsVal, std::shared_ptr<PreferencesAysncContext> context)
{
    napi_valuetype valueType = napi_undefined;
    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, jsVal, &arrLen);
    if (status != napi_ok) {
        LOG_ERROR("ParseDefObject get array failed, status = %{public}d", status);
        return E_ERROR;
    }
    napi_value flag = nullptr;
    status = napi_get_element(env, jsVal, 0, &flag);
    if (status != napi_ok) {
        LOG_ERROR("ParseDefObject get array element failed, status = %{public}d", status);
        return E_ERROR;
    }
    status = napi_typeof(env, flag, &valueType);
    if (status != napi_ok) {
        LOG_ERROR("ParseDefObject get array element type failed, status = %{public}d", status);
        return E_ERROR;
    }
    if (ParseObjectElement(valueType, env, jsVal, context) != E_OK) {
        LOG_ERROR("ParseDefObject parse array element failed, status = %{public}d", status);
        return E_ERROR;
    }
    return E_OK;
}

int ParseDefValue(const napi_env &env, const napi_value &jsVal, std::shared_ptr<PreferencesAysncContext> context)
{
    napi_valuetype valueType = napi_undefined;
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("value", "a ValueType.");
    napi_typeof(env, jsVal, &valueType);
    if (valueType == napi_number) {
        double number = 0.0;
        if (JSUtils::Convert2Double(env, jsVal, number) != E_OK) {
            LOG_ERROR("ParseDefValue Convert2Double error");
            PRE_CHECK_RETURN_CALL_RESULT(true, context->SetError(paramError));
        }
        context->defValue = number;
    } else if (valueType == napi_string) {
        std::string str;
        if (JSUtils::Convert2String(env, jsVal, str) != E_OK) {
            LOG_ERROR("ParseDefValue Convert2String error");
            PRE_CHECK_RETURN_CALL_RESULT(true, context->SetError(paramError));
        }
        context->defValue = str;
    } else if (valueType == napi_boolean) {
        bool bValue = false;
        if (JSUtils::Convert2Bool(env, jsVal, bValue) != E_OK) {
            LOG_ERROR("ParseDefValue Convert2Bool error");
            PRE_CHECK_RETURN_CALL_RESULT(true, context->SetError(paramError));
        }
        context->defValue = bValue;
    } else if (valueType == napi_object) {
        if (ParseDefObject(env, jsVal, context) != E_OK) {
            LOG_ERROR("ParseDefValue::ParseDefObject failed");
        }
    } else {
        LOG_ERROR("ParseDefValue Wrong second parameter type");
        PRE_CHECK_RETURN_CALL_RESULT(true, context->SetError(paramError));
    }
    return OK;
}

int32_t GetAllArr(const std::string &key, const PreferencesValue &value,
    std::shared_ptr<PreferencesAysncContext> context, napi_value &output)
{
    napi_value jsArr = nullptr;
    if (value.IsDoubleArray()) {
        if (JSUtils::Convert2JSDoubleArr(context->env_, value, jsArr) != E_OK) {
            LOG_ERROR("PreferencesProxy::GetAllArr Convert2JSValue failed");
            return ERR;
        }
        if (napi_set_named_property(context->env_, output, key.c_str(), jsArr) != napi_ok) {
            LOG_ERROR("PreferencesProxy::GetAllArr set property doubleArr failed");
            return ERR;
        }
    } else if (value.IsStringArray()) {
        if (JSUtils::Convert2JSStringArr(context->env_, value, jsArr) != E_OK) {
            LOG_ERROR("PreferencesProxy::GetAllArr Convert2JSValue failed");
            return ERR;
        }
        if (napi_set_named_property(context->env_, output, key.c_str(), jsArr) != napi_ok) {
            LOG_ERROR("PreferencesProxy::GetAll set property stringArr failed");
            return ERR;
        }
    } else if (value.IsBoolArray()) {
        if (JSUtils::Convert2JSBoolArr(context->env_, value, jsArr) != E_OK) {
            LOG_ERROR("PreferencesProxy::GetAllArr Convert2JSValue failed");
            return ERR;
        }

        napi_status status = napi_set_named_property(context->env_, output, key.c_str(), jsArr);
        if (status != napi_ok) {
            LOG_ERROR("PreferencesProxy::GetAll set property boolArr failed, status = %{public}d", status);
            return ERR;
        }
    }
    return OK;
}

int32_t GetAllExecute(std::shared_ptr<PreferencesAysncContext> context, napi_value &output)
{
    if (napi_create_object(context->env_, &output) != napi_ok) {
        LOG_ERROR("PreferencesProxy::GetAll creat object failed");
        return ERR;
    }
    napi_value jsVal = nullptr;
    for (const auto &[key, value] : context->allElements) {
        if (value.IsBool()) {
            if (JSUtils::Convert2JSValue(context->env_, static_cast<bool>(value), jsVal) != E_OK) {
                LOG_ERROR("PreferencesProxy::GetAll get property bool failed");
                return ERR;
            }
            if (napi_set_named_property(context->env_, output, key.c_str(), jsVal) != napi_ok) {
                LOG_ERROR("PreferencesProxy::GetAll set property bool failed");
                return ERR;
            }
        } else if (value.IsDouble()) {
            if (JSUtils::Convert2JSValue(context->env_, static_cast<double>(value), jsVal) != E_OK) {
                LOG_ERROR("PreferencesProxy::GetAll get property double failed");
                return ERR;
            }
            if (napi_set_named_property(context->env_, output, key.c_str(), jsVal) != napi_ok) {
                LOG_ERROR("PreferencesProxy::GetAll set property double failed");
                return ERR;
            }
        } else if (value.IsString()) {
            if (JSUtils::Convert2JSValue(context->env_, static_cast<std::string>(value), jsVal) != napi_ok) {
                LOG_ERROR("PreferencesProxy::GetAll get property string failed");
                return ERR;
            }
            if (napi_set_named_property(context->env_, output, key.c_str(), jsVal) != napi_ok) {
                LOG_ERROR("PreferencesProxy::GetAll set property string failed");
                return ERR;
            }
        } else {
            int errCode = GetAllArr(key, value, context, output);
            if (errCode != OK) {
                LOG_ERROR("PreferencesProxy::GetAll set property array failed");
                return ERR;
            }
        }
    }
    return OK;
}

napi_value PreferencesProxy::GetAll(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetAll start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("0 or 1");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 0 || argc == 1, context->SetError(paramNumError));
        napi_unwrap(env, self, &context->boundObj);
        return OK;
    };
    auto exec = [context]() -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        context->allElements = obj->value_->GetAll();
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        LOG_DEBUG("GetAll end.");
        return GetAllExecute(context, result);
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULLPTR(context, context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

int32_t GetArrayValue(std::shared_ptr<PreferencesAysncContext> context, napi_value &output)
{
    if (context->defValue.IsDoubleArray()) {
        if (JSUtils::Convert2JSDoubleArr(context->env_, (std::vector<double>)context->defValue, output) != E_OK) {
            LOG_ERROR("GetArrayValue Convert2JSValue get doubleArray failed");
            return E_NAPI_GET_ERROR;
        }
    } else if (context->defValue.IsStringArray()) {
        if (JSUtils::Convert2JSStringArr(context->env_, (std::vector<std::string>)context->defValue, output) != E_OK) {
            LOG_ERROR("GetArrayValue Convert2JSValue get stringArray failed");
            return E_NAPI_GET_ERROR;
        }
    } else if (context->defValue.IsBoolArray()) {
        if (JSUtils::Convert2JSBoolArr(context->env_, (std::vector<bool>)context->defValue, output) != E_OK) {
            LOG_ERROR("GetArrayValue Convert2JSValue get boolArray failed");
            return E_NAPI_GET_ERROR;
        }
    }
    return E_OK;
}

napi_value PreferencesProxy::GetValue(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetValue start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseKey(env, argv[0], context));
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseDefValue(env, argv[1], context));
        napi_unwrap(env, self, &context->boundObj);
        return OK;
    };
    auto exec = [context]() -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        context->defValue = obj->value_->Get(context->key, context->defValue);
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        int errCode = OK;
        if (context->defValue.IsBool()) {
            if (JSUtils::Convert2JSValue(context->env_, static_cast<bool>(context->defValue), result) != E_OK) {
                LOG_ERROR("PreferencesProxy::GetValue Convert2JSValue boolVal failed");
                errCode = ERR;
            }
        } else if (context->defValue.IsString()) {
            if (JSUtils::Convert2JSValue(context->env_, static_cast<std::string>(context->defValue), result) != E_OK) {
                LOG_ERROR("PreferencesProxy::GetValue Convert2JSValue stringVal failed");
                errCode = ERR;
            }
        } else if (context->defValue.IsDouble()) {
            if (JSUtils::Convert2JSValue(context->env_, static_cast<double>(context->defValue), result) != E_OK) {
                LOG_ERROR("PreferencesProxy::GetValue Convert2JSValue boolVal failed");
                errCode = ERR;
            }
        } else if (context->defValue.IsDoubleArray() || context->defValue.IsStringArray()
                   || context->defValue.IsBoolArray()) {
            if (GetArrayValue(context, result) != E_OK) {
                LOG_ERROR("PreferencesProxy::GetValue GetArrayValue failed");
                errCode = ERR;
            }
        } else {
            errCode = ERR;
        }
        LOG_DEBUG("GetValue end.");
        return errCode;
    };
    context->SetAction(env, info, input, exec, output);
    
    PRE_CHECK_RETURN_NULLPTR(context, context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value PreferencesProxy::SetValue(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("SetValue start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
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

napi_value PreferencesProxy::Delete(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Delete start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1 or 2");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2, context->SetError(paramNumError));
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

napi_value PreferencesProxy::HasKey(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("HasKey start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1 or 2");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2, context->SetError(paramNumError));
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

napi_value PreferencesProxy::Flush(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Flush start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("0 or 1");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 0 || argc == 1, context->SetError(paramNumError));
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
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("0 or 1");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 0 || argc == 1, context->SetError(paramNumError));
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

napi_value PreferencesProxy::RegisterObserver(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    size_t argc = 2;
    napi_value args[2] = { 0 };

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));
    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, args[0], &type));
    PRE_NAPI_ASSERT(env, type == napi_string, std::make_shared<ParamTypeError>("type", "string 'change'."));

    std::string chang;
    int ret = JSUtils::Convert2String(env, args[0], chang);
    PRE_NAPI_ASSERT(env, ret == OK && chang == "change", std::make_shared<ParamTypeError>("type", "string 'change'."));

    NAPI_CALL(env, napi_typeof(env, args[1], &type));
    PRE_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamTypeError>("callback", "function type."));

    PreferencesProxy *obj = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thiz, reinterpret_cast<void **>(&obj)));
    obj->RegisteredObserver(args[1]);

    return nullptr;
}

napi_value PreferencesProxy::UnRegisterObserver(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    size_t argc = 2;
    napi_value args[2] = { 0 };

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));
    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, args[0], &type));
    PRE_NAPI_ASSERT(env, type == napi_string, std::make_shared<ParamTypeError>("type", "string 'change'."));

    std::string chang;
    int ret = JSUtils::Convert2String(env, args[0], chang);
    PRE_NAPI_ASSERT(env, ret == OK && chang == "change", std::make_shared<ParamTypeError>("type", "string 'change'."));

    NAPI_CALL(env, napi_typeof(env, args[1], &type));
    PRE_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamTypeError>("callback", "function type."));

    PreferencesProxy *obj = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thiz, reinterpret_cast<void **>(&obj)));
    obj->UnRegisteredObserver(args[1]);

    return nullptr;
}

bool PreferencesProxy::HasRegisteredObserver(napi_value callback)
{
    std::lock_guard<std::mutex> lck(listMutex_);
    for (auto &it : dataObserver_) {
        if (JSUtils::Equals(env_, callback, it->GetCallback())) {
            LOG_INFO("The observer has already subscribed.");
            return true;
        }
    }
    return false;
}

void PreferencesProxy::RegisteredObserver(napi_value callback)
{
    if (!HasRegisteredObserver(callback)) {
        auto observer = std::make_shared<JSPreferencesObserver>(uvQueue_, callback);
        value_->RegisterObserver(observer);
        dataObserver_.push_back(observer);
        LOG_INFO("The observer subscribed success.");
    }
}

void PreferencesProxy::UnRegisteredObserver(napi_value callback)
{
    std::lock_guard<std::mutex> lck(listMutex_);
    auto it = dataObserver_.begin();
    while (it != dataObserver_.end()) {
        if (!JSUtils::Equals(env_, callback, (*it)->GetCallback())) {
            ++it;
            continue; // specified observer and not current iterator
        }
        value_->UnRegisterObserver(*it);
        it = dataObserver_.erase(it);
        LOG_INFO("The observer unsubscribed success.");
    }
}
} // namespace PreferencesJsKit
} // namespace OHOS
