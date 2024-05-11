/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "preferences_helper.h"

#include <string>
#include <variant>
#include <vector>
#include <map>

#include "ffi_remote_data.h"
#include "securec.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_impl.h"
#include "preferences_value.h"
#include "preferences_utils.h"
#include "preferences_errno.h"
#include "preferences_log.h"

using namespace OHOS::Preferences;
using namespace OHOS::FFI;
using namespace OHOS::NativePreferences;

namespace OHOS::Preferences {

struct ContextInfo {
    std::string bundleName;
    std::string preferencesDir;
};

std::tuple<int32_t, std::string> GetInstancePath(OHOS::AbilityRuntime::Context* context, const std::string &name,
    const std::string &dataGroupId)
{
    std::string path;
    if (context == nullptr) {
        LOGE("The context is nullptr.");
        return {E_ERROR, path};
    }
    int32_t errcode = 0;
    auto tempContext = std::make_shared<HelperAysncContext>();
    tempContext->bundleName = context->GetBundleName();
    tempContext->name = name;
    ContextInfo contextInfo;
    errcode = context->GetSystemPreferencesDir(dataGroupId, false, contextInfo.preferencesDir);
    if (errcode != 0) {
        return {errcode, path};
    }
    tempContext->path = contextInfo.preferencesDir.append("/").append(tempContext->name);
    return {E_OK, tempContext->path};
}

PreferencesImpl::PreferencesImpl(OHOS::AbilityRuntime::Context* context,
    const std::string& name, const std::string& dataGroupId, int32_t* errCode)
{
    if (context == nullptr) {
        LOGE("Failed to get native context instance");
        *errCode = -1;
        return;
    }
    auto [code, path] = GetInstancePath(context, name, dataGroupId);
    if (code != E_OK) {
        *errCode = code;
        return;
    }
    NativePreferences::Options options(path, context->GetBundleName(), dataGroupId);
    int err;
    auto proxy = PreferencesHelper::GetPreferences(options, err);
    *errCode = err;
    if (err != E_OK) {
        LOGE("Failed to get underlying preferences instance.");
        return;
    }
    preferences = proxy;
    if (preferences == nullptr) {
        LOGE("The preferences is nullptr.");
        return;
    }
}

int32_t PreferencesImpl::DeletePreferences(OHOS::AbilityRuntime::Context* context, const std::string &name,
    const std::string &dataGroupId)
{
    auto [code, path] = GetInstancePath(context, name, dataGroupId);
    if (code != E_OK) {
        return code;
    }
    int errCode = PreferencesHelper::DeletePreferences(path);
    if (errCode != E_OK) {
        return errCode;
    }
    return 0;
}

int32_t PreferencesImpl::RemovePreferencesFromCache(OHOS::AbilityRuntime::Context* context, const std::string &name,
    const std::string &dataGroupId)
{
    auto [code, path] = GetInstancePath(context, name, dataGroupId);
    if (code != 0) {
        return code;
    }
    int errCode = PreferencesHelper::RemovePreferencesFromCache(path);
    if (errCode != E_OK) {
        return errCode;
    }
    return E_OK;
}

void PreferencesImpl::Flush()
{
    if (preferences == nullptr) {
        LOGE("The preferences is nullptr.");
        return;
    }
    preferences->FlushSync();
    return;
}

void PreferencesImpl::Clear()
{
    if (preferences == nullptr) {
        LOGE("The preferences is nullptr.");
        return;
    }
    preferences->Clear();
    return;
}

int32_t PreferencesImpl::Delete(const std::string &key)
{
    if (preferences == nullptr) {
        LOGE("The preferences is nullptr.");
        return E_ERROR;
    }
    int errCode = preferences->Delete(key);
    return errCode;
}

bool PreferencesImpl::HasKey(const std::string &key)
{
    if (preferences == nullptr) {
        LOGE("The preferences is nullptr.");
        return false;
    }
    bool result = preferences->HasKey(key);
    return result;
}

bool isSameFunction(const std::function<void(std::string)> *f1, const std::function<void(std::string)> *f2)
{
    return f1 == f2;
}

bool PreferencesImpl::HasRegisteredObserver(std::function<void(std::string)> *callback, RegisterMode mode)
{
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;
    for (auto &it : observers) {
        if (isSameFunction(callback, it->m_callback)) {
            return true;
        }
    }
    return false;
}

RegisterMode PreferencesImpl::ConvertToRegisterMode(const std::string &mode)
{
    return (mode == strChange) ? RegisterMode::LOCAL_CHANGE : RegisterMode::MULTI_PRECESS_CHANGE;
}

PreferencesValue ValueTypeToPreferencesValue(const ValueType &value)
{
    NativePreferences::PreferencesValue preferencesValue = NativePreferences::PreferencesValue(-1);
    switch (value.tag) {
        case TYPE_INT: {
            preferencesValue = NativePreferences::PreferencesValue(value.integer);
            break;
        }
        case TYPE_DOU: {
            preferencesValue = NativePreferences::PreferencesValue(value.float64);
            break;
        }
        case TYPE_STR: {
            preferencesValue = NativePreferences::PreferencesValue(std::string(value.string));
            break;
        }
        case TYPE_BOOL: {
            preferencesValue = NativePreferences::PreferencesValue(value.boolean);
            break;
        }
        case TYPE_BOOLARR: {
            std::vector<bool> bools = std::vector<bool>();
            for (int64_t i = 0; i < value.boolArray.size; i++) {
                bools.push_back(value.boolArray.head[i]);
            }
            preferencesValue = NativePreferences::PreferencesValue(bools);
            break;
        }
        case TYPE_DOUARR: {
            std::vector<double> doubles = std::vector<double>();
            for (int64_t i = 0; i < value.doubleArray.size; i++) {
                doubles.push_back(value.doubleArray.head[i]);
            }
            preferencesValue = NativePreferences::PreferencesValue(doubles);
            break;
        }
        case TYPE_STRARR: {
            std::vector<std::string> strings = std::vector<std::string>();
            for (int64_t i = 0; i < value.stringArray.size; i++) {
                strings.push_back(value.stringArray.head[i]);
            }
            preferencesValue = NativePreferences::PreferencesValue(strings);
            break;
        }
        default:
            preferencesValue = NativePreferences::PreferencesValue(-1);
            break;
    }
    return preferencesValue;
}

void freeValueType(ValueType v)
{
    switch (v.tag) {
        case TYPE_STR: {
            free(v.string);
            break;
        }
        case TYPE_BOOLARR: {
            free(v.boolArray.head);
            break;
        }
        case TYPE_DOUARR: {
            free(v.doubleArray.head);
            break;
        }
        case TYPE_STRARR: {
            for (int64_t i = 0; i < v.stringArray.size; i++) {
                free(v.stringArray.head[i]);
            }
            free(v.stringArray.head);
            break;
        }
        default:
            break;
    }
}

CArrDouble vectorToDoubleArray(const std::vector<double> &doubles)
{
    double* head = (double*)malloc(doubles.size() * sizeof(double));
    if (head == nullptr) {
        return CArrDouble{0};
    }
    for (unsigned long i = 0; i < doubles.size(); i++) {
        head[i] = doubles[i];
    }
    CArrDouble doubleArray = { head, doubles.size() };
    return doubleArray;
}

CArrBool vectorToBoolArray(std::vector<bool> bools)
{
    bool* head = (bool*)malloc(bools.size() * sizeof(bool));
    if (head == nullptr) {
        return CArrBool{0};
    }
    for (unsigned long i = 0; i < bools.size(); i++) {
        head[i] = bools[i];
    }
    CArrBool boolArray = { head, bools.size() };
    return boolArray;
}

CArrStr vectorToStringArray(std::vector<std::string> strings)
{
    CArrStr strArray;
    strArray.size = static_cast<int64_t>(strings.size());
    strArray.head = (char**)malloc(strArray.size * sizeof(char*));
    if (strArray.head == nullptr) {
        return strArray;
    }
    for (int64_t i = 0; i < strArray.size; i++) {
        strArray.head[i] = (char*)malloc((strings[i].length() + 1) * sizeof(char));
        if (strArray.head[i] == nullptr) {
            return strArray;
        }
        errno_t ret = strcpy_s(strArray.head[i], (strings[i].length() + 1) * sizeof(char), strings[i].c_str());
        if (ret != EOK) {
            return strArray;
        }
    }
    return strArray;
}

ValueType PreferencesValueToValueType(const PreferencesValue &pValue)
{
    ValueType v = {0};
    if (pValue.IsInt()) {
        v.integer = (int64_t)std::get<int>(pValue.value_);
        v.tag = TYPE_INT;
    } else if (pValue.IsLong()) {
        v.integer = std::get<int64_t>(pValue.value_);
        v.tag = TYPE_INT;
    } else if (pValue.IsFloat()) {
        v.float64 = (double)std::get<float>(pValue.value_);
        v.tag = TYPE_DOU;
    } else if (pValue.IsDouble()) {
        v.float64 = std::get<double>(pValue.value_);
        v.tag = TYPE_DOU;
    } else if (pValue.IsString()) {
        auto pValueStr = std::get<std::string>(pValue.value_);
        char* pValueChar = MallocCString(pValueStr);
        v.string = pValueChar;
        v.tag = TYPE_STR;
    } else if (pValue.IsBool()) {
        v.boolean = std::get<bool>(pValue.value_);
        v.tag = TYPE_BOOL;
    } else if (pValue.IsBoolArray()) {
        auto boolVector = std::get<std::vector<bool>>(pValue.value_);
        v.boolArray = vectorToBoolArray(boolVector);
        v.tag = TYPE_BOOLARR;
    } else if (pValue.IsDoubleArray()) {
        auto doubleVector = std::get<std::vector<double>>(pValue.value_);
        v.doubleArray = vectorToDoubleArray(doubleVector);
        v.tag = TYPE_DOUARR;
    } else if (pValue.IsStringArray()) {
        auto stringVector = std::get<std::vector<std::string>>(pValue.value_);
        v.stringArray = vectorToStringArray(stringVector);
        v.tag = TYPE_STRARR;
    } else {
        v.tag = -1;
    }
    return v;
}

ValueTypes PreferencesValuesToValueTypes(const std::map<std::string, PreferencesValue> &objects)
{
    ValueTypes valueTypes;
    valueTypes.size = static_cast<int64_t>(objects.size());
    valueTypes.key = (char**)malloc(valueTypes.size * sizeof(char*));
    if (valueTypes.key == nullptr) {
        return valueTypes;
    }
    valueTypes.head = (ValueType*)malloc(valueTypes.size * sizeof(ValueType));
    if (valueTypes.head == nullptr) {
        free(valueTypes.key);
        return valueTypes;
    }
    int i = 0;
    for (auto const& [key, value] : objects) {
        // 将键转换成 char*
        valueTypes.key[i] = (char*)malloc((key.length() + 1) * sizeof(char));
        if (valueTypes.key[i] == nullptr) {
            for (int j = i - 1; j >= 0; j--) {
                free(valueTypes.key[j]);
                freeValueType(valueTypes.head[i]);
            }
            return valueTypes;
        }
        errno_t ret = strcpy_s(valueTypes.key[i], (key.length() + 1) * sizeof(char), key.c_str());
        if (ret != EOK) {
            for (int j = i - 1; j >= 0; j--) {
                free(valueTypes.key[j]);
                freeValueType(valueTypes.head[i]);
            }
            return valueTypes;
        }
        // 将值转换成 ValueType
        valueTypes.head[i] = PreferencesValueToValueType(value);
        i++;
    }
    return valueTypes;
}

ValueType PreferencesImpl::Get(const std::string &key, const ValueType &defValue)
{
    if (preferences == nullptr) {
        LOGE("The preferences is nullptr.");
        return ValueType{0};
    }
    auto result = PreferencesValueToValueType(preferences->Get(key, ValueTypeToPreferencesValue(defValue)));
    if (result.tag == defValue.tag) {
        return result;
    } else {
        return defValue;
    }
}

int32_t PreferencesImpl::Put(const std::string &key, const ValueType &value)
{
    if (preferences == nullptr) {
        LOGE("The preferences is nullptr.");
        return E_ERROR;
    }
    return preferences->Put(key, ValueTypeToPreferencesValue(value));
}

ValueTypes PreferencesImpl::GetAll()
{
    if (preferences == nullptr) {
        LOGE("The preferences is nullptr.");
        return ValueTypes{0};
    }
    return PreferencesValuesToValueTypes(preferences->GetAll());
}

int32_t PreferencesImpl::RegisterObserver(const std::string &mode, std::function<void(std::string)> *callback,
    const std::function<void(std::string)>& callbackRef)
{
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (ConvertToRegisterMode(mode) == RegisterMode::LOCAL_CHANGE) ?
                        localObservers_ : multiProcessObservers_;
    if (!HasRegisteredObserver(callback, ConvertToRegisterMode(mode))) {
        auto observer = std::make_shared<CJPreferencesObserver>(callback, callbackRef);
        if (preferences == nullptr) {
            LOGE("The preferences is nullptr.");
            return E_ERROR;
        }
        int errCode = preferences->RegisterObserver(observer, ConvertToRegisterMode(mode));
        if (errCode != E_OK) {
            return errCode;
        }
        observers.push_back(observer);
    }
    return E_OK;
}

int32_t PreferencesImpl::UnRegisterObserver(const std::string &mode, std::function<void(std::string)> *callback)
{
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (ConvertToRegisterMode(mode) == RegisterMode::LOCAL_CHANGE) ?
                        localObservers_ : multiProcessObservers_;
    auto it = observers.begin();
    if (preferences == nullptr) {
        LOGE("The preferences is nullptr.");
        return E_ERROR;
    }
    while (it != observers.end()) {
        if (isSameFunction(callback, (*it)->m_callback)) {
            int errCode = preferences->UnRegisterObserver(*it, ConvertToRegisterMode(mode));
            if (errCode != E_OK) {
                return errCode;
            }
            it = observers.erase(it);
            break; // specified observer is current iterator
        }
        ++it;
    }
    return E_OK;
}

int32_t PreferencesImpl::UnRegisteredAllObservers(const std::string &mode)
{
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (ConvertToRegisterMode(mode) == RegisterMode::LOCAL_CHANGE) ?
                        localObservers_ : multiProcessObservers_;
    bool hasFailed = false;
    int errCode = E_OK;
    if (preferences == nullptr) {
        LOGE("The preferences is nullptr.");
        return E_ERROR;
    }
    for (auto &observer : observers) {
        errCode = preferences->UnRegisterObserver(observer, ConvertToRegisterMode(mode));
        if (errCode != E_OK) {
            hasFailed = true;
        }
    }
    observers.clear();
    return hasFailed ? E_ERROR : E_OK;
}

CJPreferencesObserver::CJPreferencesObserver(std::function<void(std::string)> *callback,
    const std::function<void(std::string)>& callbackRef)
{
    if (callback == nullptr) {
        LOGI("WARNING: nullptr");
    }
    m_callback = callback;
    m_callbackRef = callbackRef;
}

void CJPreferencesObserver::OnChange(const std::string &key)
{
    m_callbackRef(key);
}
}
