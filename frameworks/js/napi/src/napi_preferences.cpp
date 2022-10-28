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
#include <cmath>
#include <limits>
#include <list>

#include "async_call.h"
#include "js_logger.h"
#include "js_utils.h"
#include "napi_preferences_error.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_value.h"
#include "securec.h"

using namespace OHOS::NativePreferences;
using namespace OHOS::PreferencesJsKit;
using namespace OHOS::RdbJsKit;

namespace OHOS {
namespace PreferencesJsKit {
#define MAX_KEY_LENGTH Preferences::MAX_KEY_LENGTH
#define MAX_VALUE_LENGTH Preferences::MAX_VALUE_LENGTH

struct PreferencesAysncContext : public AsyncCall::Context {
    std::string key;
    PreferencesValue defValue = PreferencesValue((int)0);
    std::map<std::string, PreferencesValue> allElements;
    bool hasKey;
    std::list<std::string> keysModified;
    std::vector<std::weak_ptr<PreferencesObserver>> preferencesObservers;

    PreferencesAysncContext() : Context(nullptr, nullptr)
    {
    }
    PreferencesAysncContext(InputAction input, OutputAction output)
        : Context(std::move(input), std::move(output)), hasKey(false)
    {
    }
    virtual ~PreferencesAysncContext(){};

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

static __thread napi_ref constructor_;

PreferencesProxy::PreferencesProxy(std::shared_ptr<OHOS::NativePreferences::Preferences> &value)
    : value_(value), env_(nullptr), wrapper_(nullptr)
{
}

PreferencesProxy::~PreferencesProxy()
{
    napi_delete_reference(env_, wrapper_);
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
    napi_define_class(env, "Storage", NAPI_AUTO_LENGTH, New, nullptr,
        sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors, &cons);

    napi_create_reference(env, cons, 1, &constructor_);
}

napi_status PreferencesProxy::NewInstance(napi_env env, napi_value arg, napi_value *instance)
{
    napi_status status;

    const int argc = 1;
    napi_value argv[argc] = { arg };

    napi_value cons;
    status = napi_get_reference_value(env, constructor_, &cons);
    if (status != napi_ok) {
        return status;
    }

    status = napi_new_instance(env, cons, argc, argv, instance);
    if (status != napi_ok) {
        return status;
    }

    return napi_ok;
}

napi_value PreferencesProxy::New(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_value thiz = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));
    if (thiz == nullptr) {
        LOG_WARN("get this failed");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[0], &valueType));
    NAPI_ASSERT(env, valueType == napi_string, "input type not string");
    char *path = new char[PATH_MAX];
    size_t pathLen = 0;
    napi_status status = napi_get_value_string_utf8(env, args[0], path, PATH_MAX, &pathLen);
    if (status != napi_ok) {
        LOG_ERROR("get path failed. ");
        delete[] path;
        return nullptr;
    }
    // get native object
    int errCode = 0;
    std::shared_ptr<OHOS::NativePreferences::Preferences> preference =
        OHOS::NativePreferences::PreferencesHelper::GetPreferences(path, errCode);
    delete[] path;
    NAPI_ASSERT(env, preference != nullptr, "failed to call native");
    PreferencesProxy *obj = new PreferencesProxy(preference);
    obj->env_ = env;
    NAPI_CALL(env, napi_wrap(env, thiz, obj, PreferencesProxy::Destructor,
                       nullptr, // finalize_hint
                       &obj->wrapper_));
    return thiz;
}

bool IsFloat(double input)
{
    return abs(input - floor(input)) >= 0; // DBL_EPSILON;
}

int ParseKey(const napi_env &env, const napi_value &arg, std::shared_ptr<PreferencesAysncContext > context)
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

int32_t ParseBoolElement(
    const napi_env &env, const napi_value &jsVal, std::shared_ptr<PreferencesAysncContext > context)
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

int32_t ParseDefObject(const napi_env &env, const napi_value &jsVal, std::shared_ptr<PreferencesAysncContext > context)
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
        if (JSUtils::Convert2JSDoubleArr(context->_env, (std::vector<double>)value, jsArr) != E_OK) {
            LOG_ERROR("PreferencesProxy::GetAllArr Convert2JSValue failed");
            return ERR;
        }
        if (napi_set_named_property(context->_env, output, key.c_str(), jsArr) != napi_ok) {
            LOG_ERROR("PreferencesProxy::GetAllArr set property doubleArr failed");
            return ERR;
        }
    } else if (value.IsStringArray()) {
        if (JSUtils::Convert2JSStringArr(context->_env, (std::vector<std::string>)value, jsArr) != E_OK) {
            LOG_ERROR("PreferencesProxy::GetAllArr Convert2JSValue failed");
            return ERR;
        }
        if (napi_set_named_property(context->_env, output, key.c_str(), jsArr) != napi_ok) {
            LOG_ERROR("PreferencesProxy::GetAll set property stringArr failed");
            return ERR;
        }
    } else if (value.IsBoolArray()) {
        if (JSUtils::Convert2JSBoolArr(context->_env, (std::vector<bool>)value, jsArr) != E_OK) {
            LOG_ERROR("PreferencesProxy::GetAllArr Convert2JSValue failed");
            return ERR;
        }

        napi_status status = napi_set_named_property(context->_env, output, key.c_str(), jsArr);
        if (status != napi_ok) {
            LOG_ERROR("PreferencesProxy::GetAll set property boolArr failed, status = %{public}d", status);
            return ERR;
        }
    }
    return OK;
}

int32_t GetAllExecute(std::shared_ptr<PreferencesAysncContext > context, napi_value &output)
{
    if (napi_create_object(context->_env, &output) != napi_ok) {
        LOG_ERROR("PreferencesProxy::GetAll creat object failed");
        return ERR;
    }
    napi_value jsVal = nullptr;
    for (const auto &[key, value] : context->allElements) {
        if (value.IsBool()) {
            if (JSUtils::Convert2JSValue(context->_env, (bool)value, jsVal) != E_OK) {
                LOG_ERROR("PreferencesProxy::GetAll get property bool failed");
                return ERR;
            }
            if (napi_set_named_property(context->_env, output, key.c_str(), jsVal) != napi_ok) {
                LOG_ERROR("PreferencesProxy::GetAll set property bool failed");
                return ERR;
            }
        } else if (value.IsDouble()) {
            if (JSUtils::Convert2JSValue(context->_env, (double)value, jsVal) != E_OK) {
                LOG_ERROR("PreferencesProxy::GetAll get property double failed");
                return ERR;
            }
            if (napi_set_named_property(context->_env, output, key.c_str(), jsVal) != napi_ok) {
                LOG_ERROR("PreferencesProxy::GetAll set property double failed");
                return ERR;
            }
        } else if (value.IsString()) {
            if (JSUtils::Convert2JSValue(context->_env, (std::string)value, jsVal) != napi_ok) {
                LOG_ERROR("PreferencesProxy::GetAll get property string failed");
                return ERR;
            }
            if (napi_set_named_property(context->_env, output, key.c_str(), jsVal) != napi_ok) {
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
        return OK;
    };
    auto exec = [context](AsyncCall::Context *ctx) -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        context->allElements = obj->value_->GetAll();
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        LOG_DEBUG("GetAll end.");
        return GetAllExecute(context, result);
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    PRE_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return asyncCall.Call(env, exec);
}

int32_t GetArrayValue(std::shared_ptr<PreferencesAysncContext > context, napi_value &output)
{
    if (context->defValue.IsDoubleArray()) {
        if (JSUtils::Convert2JSDoubleArr(context->_env, (std::vector<double>)context->defValue, output)
            != E_OK) {
            LOG_ERROR("GetArrayValue Convert2JSValue get doubleArray failed");
            return E_NAPI_GET_ERROR;
        }
    } else if (context->defValue.IsStringArray()) {
        if (JSUtils::Convert2JSStringArr(context->_env, (std::vector<std::string>)context->defValue, output)
            != E_OK) {
            LOG_ERROR("GetArrayValue Convert2JSValue get stringArray failed");
            return E_NAPI_GET_ERROR;
        }
    } else if (context->defValue.IsBoolArray()) {
        std::vector<bool> array = context->defValue;
        if (JSUtils::Convert2JSBoolArr(context->_env, (std::vector<bool>)context->defValue, output) != E_OK) {
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
        return OK;
    };
    auto exec = [context](AsyncCall::Context *ctx) -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        context->defValue = obj->value_->Get(context->key, context->defValue);
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        int errCode = OK;
        if (context->defValue.IsBool()) {
            if (JSUtils::Convert2JSValue(context->_env, (bool)context->defValue, result) != E_OK) {
                LOG_ERROR("PreferencesProxy::GetValue Convert2JSValue boolVal failed");
                errCode = ERR;
            }
        } else if (context->defValue.IsString()) {
            if (JSUtils::Convert2JSValue(context->_env, (std::string)context->defValue, result) != E_OK) {
                LOG_ERROR("PreferencesProxy::GetValue Convert2JSValue stringVal failed");
                errCode = ERR;
            }
        } else if (context->defValue.IsDouble()) {
            if (JSUtils::Convert2JSValue(context->_env, (double)context->defValue, result) != E_OK) {
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
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    PRE_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return asyncCall.Call(env, exec);
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
        return OK;
    };
    auto exec = [context](AsyncCall::Context *ctx) -> int {
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
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    PRE_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return asyncCall.Call(env, exec);
}

napi_value PreferencesProxy::Delete(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Delete start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1 or 2");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2, context->SetError(paramNumError));
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseKey(env, argv[0], context));
        return OK;
    };
    auto exec = [context](AsyncCall::Context *ctx) -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        int errCode = obj->value_->Delete(context->key);
        return (errCode == OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("Delete end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    PRE_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return asyncCall.Call(env, exec);
}

napi_value PreferencesProxy::HasKey(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("HasKey start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1 or 2");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2, context->SetError(paramNumError));
        PRE_ASYNC_PARAM_CHECK_FUNCTION(ParseKey(env, argv[0], context));
        return OK;
    };
    auto exec = [context](AsyncCall::Context *ctx) -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        context->hasKey = obj->value_->HasKey(context->key);
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_boolean(env, context->hasKey, &result);
        LOG_DEBUG("HasKey end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    PRE_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return asyncCall.Call(env, exec);
}

napi_value PreferencesProxy::Flush(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Flush start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("0 or 1");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 0 || argc == 1, context->SetError(paramNumError));
        return OK;
    };
    auto exec = [context](AsyncCall::Context *ctx) -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        return obj->value_->FlushSync();
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("Flush end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    PRE_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return asyncCall.Call(env, exec);
}

napi_value PreferencesProxy::Clear(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("Clear start");
    auto context = std::make_shared<PreferencesAysncContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("0 or 1");
        PRE_CHECK_RETURN_CALL_RESULT(argc == 0 || argc == 1, context->SetError(paramNumError));
        return OK;
    };
    auto exec = [context](AsyncCall::Context *ctx) -> int {
        PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(context->boundObj);
        return obj->value_->Clear();
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("Clear end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    PRE_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return asyncCall.Call(env, exec);
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

    NAPI_CALL(env, napi_typeof(env, args[1], &type));
    PRE_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamTypeError>("callback", "function type."));

    PreferencesProxy *obj = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thiz, reinterpret_cast<void **>(&obj)));

    // reference save
    obj->observer_ = std::make_shared<PreferencesObserverImpl>(env, args[1]);
    obj->value_->RegisterObserver(obj->observer_);
    LOG_DEBUG("RegisterObserver end");

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

    NAPI_CALL(env, napi_typeof(env, args[1], &type));
    PRE_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamTypeError>("callback", "function type."));

    PreferencesProxy *obj = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thiz, reinterpret_cast<void **>(&obj)));
    obj->value_->UnRegisterObserver(obj->observer_);
    obj->observer_.reset();
    obj->observer_ = nullptr;
    LOG_DEBUG("UnRegisterObserver end");
    return nullptr;
}

PreferencesObserverImpl::PreferencesObserverImpl(napi_env env, napi_value callback) : NapiUvQueue(env, callback)
{
}

PreferencesObserverImpl::~PreferencesObserverImpl()
{
}

void PreferencesObserverImpl::OnChange(const std::string &key)
{
    CallFunction([key](napi_env env, int &argc, napi_value *argv) {
        argc = 1;
        int status = JSUtils::Convert2JSValue(env, key, argv[0]);
        if (status != OK) {
            LOG_DEBUG("OnChange CallFunction error.");
        }
    });
    LOG_DEBUG("OnChange key end");
}
} // namespace PreferencesJsKit
} // namespace OHOS
