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

#include "adaptor.h"

#include <cerrno>
#include <cmath>
#include <limits>
#include <list>

#include "js_logger.h"
#include "js_utils.h"
#include "napi_async_proxy_v9.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_value.h"
#include "securec.h"

using namespace OHOS::NativePreferences;
using namespace OHOS::AppDataMgrJsKit;
using namespace OHOS::RdbJsKit;

namespace OHOS {
namespace PreferencesJsKit {
#define MAX_KEY_LENGTH Preferences::MAX_KEY_LENGTH
#define MAX_VALUE_LENGTH Preferences::MAX_VALUE_LENGTH

struct PreferencesAysncContext : NapiAsyncProxyV9<PreferencesAysncContext>::AysncContext {
    std::string key;
    PreferencesValue defValue = PreferencesValue((int)0);
    std::map<std::string, PreferencesValue> allElements;
    bool hasKey;
    std::list<std::string> keysModified;
    std::vector<std::weak_ptr<PreferencesObserver>> preferencesObservers;
    std::string execMessage = "";
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
    napi_define_class(env, "Preferences", NAPI_AUTO_LENGTH, New, nullptr,
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

template<typename T> bool CheckNumberType(double input)
{
    if (input > (std::numeric_limits<T>::max)() || input < (std::numeric_limits<T>::min)()) {
        return false;
    }
    return true;
}

bool IsFloat(double input)
{
    return abs(input - floor(input)) >= 0; // DBL_EPSILON;
}

bool ParseKey(const napi_env &env, const napi_value &arg, std::string &parmName, std::string &parmType, PreferencesAysncContext *asyncContext)
{
    parmName = "key";
    parmType = "no empty string.";
    // get input key
    char key[MAX_KEY_LENGTH] = { 0 };
    size_t keySize = 0;
    napi_status status = napi_get_value_string_utf8(env, arg, key, MAX_KEY_LENGTH, &keySize);
    if (status != napi_ok) {
        return false;
    }
    asyncContext->key = key;
    return true;
}

int32_t ParseDoubleElement(const napi_env &env, const napi_value &jsVal, PreferencesAysncContext *asyncContext)
{
    std::vector<double> array;
    if (JSUtils::Convert2DoubleVector(env, jsVal, array) != E_OK) {
        LOG_ERROR("ParseDoubleElement Convert2DoubleVector failed");
        return E_ERROR;
    }
    asyncContext->defValue = array;
    return E_OK;
}

int32_t ParseBoolElement(const napi_env &env, const napi_value &jsVal, PreferencesAysncContext *asyncContext)
{
    std::vector<bool> array;
    if (JSUtils::Convert2BoolVector(env, jsVal, array) != E_OK) {
        LOG_ERROR("ParseBoolElement Convert2BoolVector failed");
        return E_ERROR;
    }
    asyncContext->defValue = array;
    return E_OK;
}

int32_t ParseStringElement(const napi_env &env, const napi_value &jsVal, PreferencesAysncContext *asyncContext)
{
    std::vector<std::string> array;
    if (JSUtils::Convert2StrVector(env, jsVal, array) != E_OK) {
        LOG_ERROR("ParseStringElement Convert2StrVector failed");
        return E_ERROR;
    }
    asyncContext->defValue = array;
    return E_OK;
}

int32_t ParseObjectElement(
    napi_valuetype valueType, const napi_env &env, const napi_value &jsVal, PreferencesAysncContext *asyncContext)
{
    if (valueType == napi_number) {
        return ParseDoubleElement(env, jsVal, asyncContext);
    } else if (valueType == napi_boolean) {
        return ParseBoolElement(env, jsVal, asyncContext);
    } else if (valueType == napi_string) {
        return ParseStringElement(env, jsVal, asyncContext);
    } else {
        LOG_ERROR("ParseObjectElement unexpected valueType");
        return E_ERROR;
    }
}

int32_t ParseDefObject(const napi_env &env, const napi_value &jsVal, PreferencesAysncContext *asyncContext)
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
    if (ParseObjectElement(valueType, env, jsVal, asyncContext) != E_OK) {
        LOG_ERROR("ParseDefObject parse array element failed, status = %{public}d", status);
        return E_ERROR;
    }
    return E_OK;
}

bool ParseDefValue(const napi_env &env, const napi_value &jsVal, std::string &parmName, std::string &parmType, PreferencesAysncContext *asyncContext)
{
    parmName = "value";
    parmType = "ValueType.";
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, jsVal, &valueType);
    if (valueType == napi_number) {
        double number = 0.0;
        if (JSUtils::Convert2Double(env, jsVal, number) != E_OK) {
            LOG_ERROR("ParseDefValue Convert2Double error");
            return false;
        }
        asyncContext->defValue = number;
    } else if (valueType == napi_string) {
        std::string str;
        if (JSUtils::Convert2String(env, jsVal, str) != E_OK) {
            LOG_ERROR("ParseDefValue Convert2String error");
            return false;
        }
        asyncContext->defValue = str;
    } else if (valueType == napi_boolean) {
        bool bValue = false;
        if (JSUtils::Convert2Bool(env, jsVal, bValue) != E_OK) {
            LOG_ERROR("ParseDefValue Convert2Bool error");
            return false;
        }
        asyncContext->defValue = bValue;
    } else if (valueType == napi_object) {
        if (ParseDefObject(env, jsVal, asyncContext) != E_OK) {
            LOG_ERROR("ParseDefValue::ParseDefObject failed");
            return false;
        }
    } else {
        LOG_ERROR("ParseDefValue Wrong second parameter type");
        return false;
    }
    return true;
}

int32_t GetAllArr(
    const std::string &key, const PreferencesValue &value, PreferencesAysncContext *asyncContext, napi_value &output)
{
    napi_value jsArr = nullptr;
    if (value.IsDoubleArray()) {
        if (JSUtils::Convert2JSDoubleArr(asyncContext->env, (std::vector<double>)value, jsArr) != E_OK) {
            LOG_ERROR("PreferencesProxy::GetAllArr Convert2JSValue failed");
            return E_ERROR;
        }
        if (napi_set_named_property(asyncContext->env, output, key.c_str(), jsArr) != napi_ok) {
            LOG_ERROR("PreferencesProxy::GetAllArr set property doubleArr failed");
            return E_ERROR;
        }
    } else if (value.IsStringArray()) {
        if (JSUtils::Convert2JSStringArr(asyncContext->env, (std::vector<std::string>)value, jsArr) != E_OK) {
            LOG_ERROR("PreferencesProxy::GetAllArr Convert2JSValue failed");
            return E_ERROR;
        }
        if (napi_set_named_property(asyncContext->env, output, key.c_str(), jsArr) != napi_ok) {
            LOG_ERROR("PreferencesProxy::GetAll set property stringArr failed");
            return E_ERROR;
        }
    } else if (value.IsBoolArray()) {
        if (JSUtils::Convert2JSBoolArr(asyncContext->env, (std::vector<bool>)value, jsArr) != E_OK) {
            LOG_ERROR("PreferencesProxy::GetAllArr Convert2JSValue failed");
            return E_ERROR;
        }

        napi_status status = napi_set_named_property(asyncContext->env, output, key.c_str(), jsArr);
        if (status != napi_ok) {
            LOG_ERROR("PreferencesProxy::GetAll set property boolArr failed, status = %{public}d", status);
            return E_ERROR;
        }
    }
    return E_OK;
}

int32_t GetAllExecute(PreferencesAysncContext *asyncContext, std::string &errorMessage, napi_value &output)
{
    if (napi_create_object(asyncContext->env, &output) != napi_ok) {
        return ERR;
    }
    napi_value jsVal = nullptr;
    for (const auto &[key, value] : asyncContext->allElements) {
        if (value.IsBool()) {
            if (JSUtils::Convert2JSValue(asyncContext->env, (bool)value, jsVal) != E_OK) {
                return ERR;
            }
            if (napi_set_named_property(asyncContext->env, output, key.c_str(), jsVal) != napi_ok) {
                return ERR;
            }
        } else if (value.IsDouble()) {
            if (JSUtils::Convert2JSValue(asyncContext->env, (double)value, jsVal) != E_OK) {
                return ERR;
            }
            if (napi_set_named_property(asyncContext->env, output, key.c_str(), jsVal) != napi_ok) {
                return ERR;
            }
        } else if (value.IsString()) {
            std::string tempStr = (std::string)value;
            if (JSUtils::Convert2JSValue(asyncContext->env, (std::string)value, jsVal) != napi_ok) {
                return ERR;
            }
            if (napi_set_named_property(asyncContext->env, output, key.c_str(), jsVal) != napi_ok) {
                return ERR;
            }
        } else {
            int errCode = GetAllArr(key, value, asyncContext, output);
            if (errCode != E_OK) {
                return ERR;
            }
        }
    }
    return E_OK;
}

napi_value PreferencesProxy::GetAll(napi_env env, napi_callback_info info)
{
    NapiAsyncProxyV9<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxyV9<PreferencesAysncContext>::InputParser> parsers;
    if (!proxy.ParseInputs(parsers)) {
        return nullptr;
    }
    return proxy.DoAsyncWork(
        "GetAll",
        [](PreferencesAysncContext *asyncContext, std::string &errorMessage) {
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            asyncContext->allElements = obj->value_->GetAll();
            return E_OK;
        },
        GetAllExecute);
}

int32_t GetArrayValue(PreferencesAysncContext *asyncContext, napi_value &output)
{
    if (asyncContext->defValue.IsDoubleArray()) {
        if (JSUtils::Convert2JSDoubleArr(asyncContext->env, (std::vector<double>)asyncContext->defValue, output)
            != E_OK) {
            LOG_ERROR("GetArrayValue Convert2JSValue get doubleArray failed");
            return E_NAPI_GET_ERROR;
        }
    } else if (asyncContext->defValue.IsStringArray()) {
        if (JSUtils::Convert2JSStringArr(asyncContext->env, (std::vector<std::string>)asyncContext->defValue, output)
            != E_OK) {
            LOG_ERROR("GetArrayValue Convert2JSValue get stringArray failed");
            return E_NAPI_GET_ERROR;
        }
    } else if (asyncContext->defValue.IsBoolArray()) {
        std::vector<bool> array = asyncContext->defValue;
        if (JSUtils::Convert2JSBoolArr(asyncContext->env, (std::vector<bool>)asyncContext->defValue, output) != E_OK) {
            LOG_ERROR("GetArrayValue Convert2JSValue get boolArray failed");
            return E_NAPI_GET_ERROR;
        }
    }
    return E_OK;
}

napi_value PreferencesProxy::GetValue(napi_env env, napi_callback_info info)
{
    NapiAsyncProxyV9<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxyV9<PreferencesAysncContext>::InputParser> parsers;
    parsers.push_back(ParseKey);
    parsers.push_back(ParseDefValue);
    if (!proxy.ParseInputs(parsers)) {
        return nullptr;
    }
    return proxy.DoAsyncWork(
        "GetValue",
        [](PreferencesAysncContext *asyncContext, std::string &errorMessage) {
            int errCode = E_OK;
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            asyncContext->defValue = obj->value_->Get(asyncContext->key, asyncContext->defValue);
            return (errCode == E_OK) ? OK : ERR;
        },
        [](PreferencesAysncContext *asyncContext, std::string &errorMessage, napi_value &output) {
            int errCode = E_OK;
            if (asyncContext->defValue.IsBool()) {
                if (JSUtils::Convert2JSValue(asyncContext->env, (bool)asyncContext->defValue, output) != E_OK) {
                    errCode = ERR;
                }
            } else if (asyncContext->defValue.IsString()) {
                if (JSUtils::Convert2JSValue(asyncContext->env, (std::string)asyncContext->defValue, output) != E_OK) {
                    errCode = ERR;
                }
            } else if (asyncContext->defValue.IsDouble()) {
                if (JSUtils::Convert2JSValue(asyncContext->env, (double)asyncContext->defValue, output) != E_OK) {
                    errCode = ERR;
                }
            } else if (asyncContext->defValue.IsDoubleArray() || asyncContext->defValue.IsStringArray()
                       || asyncContext->defValue.IsBoolArray()) {
                if (GetArrayValue(asyncContext, output) != E_OK) {
                    errCode = ERR;
                }
            } else {
                errCode = ERR;
            }

            return errCode;
        });
}


napi_value PreferencesProxy::SetValue(napi_env env, napi_callback_info info)
{
    NapiAsyncProxyV9<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxyV9<PreferencesAysncContext>::InputParser> parsers;
    parsers.push_back(ParseKey);
    parsers.push_back(ParseDefValue);
    if (!proxy.ParseInputs(parsers)) {
        return nullptr;
    }
    return proxy.DoAsyncWork(
        "SetValue",
        [](PreferencesAysncContext *asyncContext, std::string &errorMessage) {
            int errCode = E_ERROR;
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            errCode = obj->value_->Put(asyncContext->key, asyncContext->defValue);
            return (errCode == E_OK) ? OK : ERR;
        },
        [](PreferencesAysncContext *asyncContext, std::string &errorMessage, napi_value &output) {
            napi_status status = napi_get_undefined(asyncContext->env, &output);
            return (status == napi_ok) ? E_OK : ERR;
        });
}

napi_value PreferencesProxy::Delete(napi_env env, napi_callback_info info)
{
    NapiAsyncProxyV9<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxyV9<PreferencesAysncContext>::InputParser> parsers;
    parsers.push_back(ParseKey);
    if (!proxy.ParseInputs(parsers)) {
        return nullptr;
    }
    return proxy.DoAsyncWork(
        "Delete",
        [](PreferencesAysncContext *asyncContext, std::string &errorMessage) {
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            int errCode = obj->value_->Delete(asyncContext->key);
            return (errCode == E_OK) ? OK : ERR;
        },
        [](PreferencesAysncContext *asyncContext, std::string &errorMessage, napi_value &output) {
            napi_status status = napi_get_undefined(asyncContext->env, &output);
            return (status == napi_ok) ? E_OK : ERR;
        });
}

napi_value PreferencesProxy::HasKey(napi_env env, napi_callback_info info)
{
    NapiAsyncProxyV9<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxyV9<PreferencesAysncContext>::InputParser> parsers;
    parsers.push_back(ParseKey);
    if (!proxy.ParseInputs(parsers)) {
        return nullptr;
    }
    return proxy.DoAsyncWork(
        "HasKey",
        [](PreferencesAysncContext *asyncContext, std::string &errorMessage) {
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            asyncContext->hasKey = obj->value_->HasKey(asyncContext->key);
            return OK;
        },
        [](PreferencesAysncContext *asyncContext, std::string &errorMessage, napi_value &output) {
            napi_status status = napi_get_boolean(asyncContext->env, asyncContext->hasKey, &output);
            return (status == napi_ok) ? OK : ERR;
        });
}

napi_value PreferencesProxy::Flush(napi_env env, napi_callback_info info)
{
    NapiAsyncProxyV9<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxyV9<PreferencesAysncContext>::InputParser> parsers;
    if (!proxy.ParseInputs(parsers)) {
        return nullptr;
    }
    return proxy.DoAsyncWork(
        "Flush",
        [](PreferencesAysncContext *asyncContext, std::string &errorMessage) {
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            int errCode = obj->value_->FlushSync();
            return (errCode == E_OK) ? OK : ERR;
        },
        [](PreferencesAysncContext *asyncContext, std::string &errorMessage, napi_value &output) {
            napi_status status = napi_get_undefined(asyncContext->env, &output);
            return (status == napi_ok) ? OK : ERR;
        });
}

napi_value PreferencesProxy::Clear(napi_env env, napi_callback_info info)
{
    NapiAsyncProxyV9<PreferencesAysncContext> proxy;
    proxy.Init(env, info);
    std::vector<NapiAsyncProxyV9<PreferencesAysncContext>::InputParser> parsers;
    if (!proxy.ParseInputs(parsers)) {
        return nullptr;
    }
    return proxy.DoAsyncWork(
        "Clear",
        [](PreferencesAysncContext *asyncContext, std::string &errorMessage) {
            PreferencesProxy *obj = reinterpret_cast<PreferencesProxy *>(asyncContext->boundObj);
            int errCode = obj->value_->Clear();
            return (errCode == E_OK) ? OK : ERR;
        },
        [](PreferencesAysncContext *asyncContext, std::string &errorMessage, napi_value &output) {
            napi_status status = napi_get_undefined(asyncContext->env, &output);
            return (status == napi_ok) ? OK : ERR;
        });
}

napi_value PreferencesProxy::RegisterObserver(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    size_t argc = 2;
    napi_value args[2] = { 0 };

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thiz, nullptr));
    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, args[0], &type));
    if(type != napi_string){
        NapiThrowError::ThrowParameterCodeError(env, "type", "'change'.");
        return nullptr;
    }

    NAPI_CALL(env, napi_typeof(env, args[1], &type));
    if(type != napi_function){
        NapiThrowError::ThrowParameterCodeError(env, "callback", "function type.");
        return nullptr;
    }

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
    if(type != napi_string){
        NapiThrowError::ThrowParameterCodeError(env, "type", "'change'.");
        return nullptr;
    }

    NAPI_CALL(env, napi_typeof(env, args[1], &type));
    if(type != napi_function){
        NapiThrowError::ThrowParameterCodeError(env, "callback", "function type.");
        return nullptr;
    }

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
    LOG_DEBUG("OnChange key:%{public}s", key.c_str());

    CallFunction([key](napi_env env, int &argc, napi_value *argv) {
        argc = 1;
        argv[0] = JSUtils::Convert2JSValue(env, key);
    });
    LOG_DEBUG("OnChange key end");
}
} // namespace PreferencesJsKit
} // namespace OHOS
