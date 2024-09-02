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

#include "oh_preferences.h"

#include "convertor_error_code.h"
#include "log_print.h"

#include "oh_preferences_err_code.h"
#include "oh_preferences_impl.h"
#include "oh_preferences_value_impl.h"
#include "oh_preferences_value.h"
#include "preferences_file_operation.h"
#include "preferences_helper.h"

using namespace OHOS::PreferencesNdk;

OH_PreferencesImpl::OH_PreferencesImpl
    (std::shared_ptr<OHOS::NativePreferences::Preferences> preferences) : preferences_(preferences)
{
}

OH_Preferences *OH_Preferences_Open(OH_PreferencesOption *options, int *errCode)
{
    if (options == nullptr || options->filePath.empty()) {
        LOG_ERROR("open store config error, options is null: %{public}d, filePath is null: %{public}d",
            (options == nullptr), options->filePath.empty());
        return nullptr;
    }

    OHOS::NativePreferences::Options nativeOptions(std::string(options->filePath), std::string(options->bundleName),
        std::string(options->dataGroupId), true);

    std::shared_ptr<OHOS::NativePreferences::Preferences> store =
        OHOS::NativePreferences::PreferencesHelper::GetPreferences(nativeOptions, *errCode);
    *errCode = ConvertorErrorCode::NativeErrToNdk(*errCode);

    if (store == nullptr) {
        LOG_ERROR("Get Preferences Store failed %{public}s",
            OHOS::NativePreferences::ExtractFileName(nativeOptions.filePath).c_str());
        return nullptr;
    }
    OH_PreferencesImpl *spStore = new(std::nothrow) OH_PreferencesImpl(store);
    spStore->SetPreferencesStoreFilePath(std::string(options->filePath));

    return spStore;
}

static OH_PreferencesImpl *GetPreferencesImpl(OH_Preferences *store)
{
    if (store == nullptr) {
        LOG_ERROR("store invalid, wichi is null");
        return nullptr;
    }
    return static_cast<OH_PreferencesImpl *>(store);
}

void OH_PreferencesImpl::SetPreferencesStoreFilePath(const std::string &filePath)
{
    std::unique_lock<std::shared_mutex> writeLock(mutex_);
    filePath_ = filePath;
}

std::string OH_PreferencesImpl::GetPreferencesStoreFilePath()
{
    std::shared_lock<std::shared_mutex> readLock(mutex_);
    return filePath_;
}

int OH_Preferences_Close(OH_Preferences *preference)
{
    auto preferencesImpl = GetPreferencesImpl(preference);
    if (preferencesImpl == nullptr) {
        LOG_ERROR("preferences close failed, preferences is null");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    std::shared_ptr<OHOS::NativePreferences::Preferences> nativePreferences = preferencesImpl->GetNativePreferences();
    if (nativePreferences == nullptr) {
        LOG_ERROR("preference not open yet");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    nativePreferences->FlushSync();

    int errCode = OHOS::NativePreferences::PreferencesHelper::RemovePreferencesFromCache(
        preferencesImpl->GetPreferencesStoreFilePath());
    if (errCode != OHOS::NativePreferences::E_OK) {
        LOG_ERROR("preference close store failed: %{public}d", errCode);
        return ConvertorErrorCode::NativeErrToNdk(errCode);
    }
    delete preferencesImpl;
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_Preferences_GetInt(OH_Preferences *preference, const char *key, int *value)
{
    auto preferencesImpl = GetPreferencesImpl(preference);
    if (preferencesImpl == nullptr || key == nullptr) {
        LOG_ERROR("get int failed, preference is null: %{public}d, key is null: %{public}d",
            (preferencesImpl == nullptr), (key == nullptr));
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    std::shared_ptr<OHOS::NativePreferences::Preferences> nativePreferences = preferencesImpl->GetNativePreferences();
    if (nativePreferences == nullptr) {
        LOG_ERROR("preference not open yet");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    auto res = nativePreferences->GetValue(key, OHOS::NativePreferences::PreferencesValue());
    if (res.second.IsInt()) {
        *value = (int)(res.second);
    } else {
        LOG_ERROR("Get Int failed, value's type is not int");
    }

    return ConvertorErrorCode::NativeErrToNdk(res.first);
}

int OH_Preferences_GetString(OH_Preferences *preference, const char *key, char **value,
    uint32_t *valueLen)
{
    auto preferencesImpl = GetPreferencesImpl(preference);
    if (preferencesImpl == nullptr || key == nullptr) {
        LOG_ERROR("get string failed, preference is null: %{public}d, key is null: %{public}d",
            (preferencesImpl == nullptr), (key == nullptr));
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    std::shared_ptr<OHOS::NativePreferences::Preferences> nativePreferences = preferencesImpl->GetNativePreferences();
    if (nativePreferences == nullptr) {
        LOG_ERROR("preference not open yet");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    auto res = nativePreferences->GetValue(key, OHOS::NativePreferences::PreferencesValue());
    if (res.second.IsString()) {
        std::string str = (std::string)(res.second);
        void *ptr = malloc(str.size() + 1); // free by caller
        if (ptr == nullptr) {
            LOG_ERROR("malloc failed when get string, errno: %{public}d", errno);
            return OH_Preferences_ErrCode::PREFERENCES_ERROR_MALLOC;
        }
        *value = (char *)ptr;
        for (size_t i = 0; i < str.size() + 1; i++) {
            (*value)[i] = (char)str[i];
        }
        (*value)[str.size()] = '\0';
        *valueLen = str.size() + 1;
    } else {
        LOG_ERROR("Get string failed, value's type is not string");
    }

    return ConvertorErrorCode::NativeErrToNdk(res.first);
}

void OH_Preferences_FreeString(char *string)
{
    if (string == nullptr) {
        LOG_ERROR("free string failed, string is null");
        return;
    }
    free(string);
}

int OH_Preferences_GetBool(OH_Preferences *preference, const char *key, bool *value)
{
    auto preferencesImpl = GetPreferencesImpl(preference);
    if (preferencesImpl == nullptr || key == nullptr) {
        LOG_ERROR("get bool failed, preference is null: %{public}d, key is null: %{public}d",
            (preferencesImpl == nullptr), (key == nullptr));
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    std::shared_ptr<OHOS::NativePreferences::Preferences> nativePreferences = preferencesImpl->GetNativePreferences();
    if (nativePreferences == nullptr) {
        LOG_ERROR("preference not open yet");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    auto res = nativePreferences->GetValue(key, OHOS::NativePreferences::PreferencesValue());
    if (res.second.IsBool()) {
        *value = (bool)(res.second);
    } else {
        LOG_ERROR("Get bool failed, value's type is not bool");
    }

    return ConvertorErrorCode::NativeErrToNdk(res.first);
}

int OH_Preferences_SetInt(OH_Preferences *preference, const char *key, int value)
{
    auto preferencesImpl = GetPreferencesImpl(preference);
    if (preferencesImpl == nullptr || key == nullptr) {
        LOG_ERROR("set int failed, preference is null: %{public}d, key is null: %{public}d",
            (preferencesImpl == nullptr), (key == nullptr));
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    std::shared_ptr<OHOS::NativePreferences::Preferences> nativePreferences = preferencesImpl->GetNativePreferences();
    if (nativePreferences == nullptr) {
        LOG_ERROR("preference not open yet");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    int errCode = nativePreferences->PutInt(key, value);
    if (errCode != OHOS::NativePreferences::E_OK) {
        LOG_ERROR("preference put int failed");
    }
    return ConvertorErrorCode::NativeErrToNdk(errCode);
}

int OH_Preferences_SetBool(OH_Preferences *preference, const char *key, bool value)
{
    auto preferencesImpl = GetPreferencesImpl(preference);
    if (preferencesImpl == nullptr || key == nullptr) {
        LOG_ERROR("set bool failed, preference is null: %{public}d, key is null: %{public}d",
            (preferencesImpl == nullptr), (key == nullptr));
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    std::shared_ptr<OHOS::NativePreferences::Preferences> nativePreferences = preferencesImpl->GetNativePreferences();
    if (nativePreferences == nullptr) {
        LOG_ERROR("preference not open yet");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    int errCode = nativePreferences->PutBool(key, value);
    if (errCode != OHOS::NativePreferences::E_OK) {
        LOG_ERROR("preference put bool failed");
    }
    return ConvertorErrorCode::NativeErrToNdk(errCode);
}

int OH_Preferences_SetString(OH_Preferences *preference, const char *key, const char *value)
{
    auto preferencesImpl = GetPreferencesImpl(preference);
    if (preferencesImpl == nullptr || key == nullptr) {
        LOG_ERROR("set string failed, preference is null: %{public}d, key is null: %{public}d",
            (preferencesImpl == nullptr), (key == nullptr));
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    std::shared_ptr<OHOS::NativePreferences::Preferences> nativePreferences = preferencesImpl->GetNativePreferences();
    if (nativePreferences == nullptr) {
        LOG_ERROR("preference not open yet");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    int errCode = nativePreferences->PutString(key, value);
    if (errCode != OHOS::NativePreferences::E_OK) {
        LOG_ERROR("preference put string failed");
    }
    return ConvertorErrorCode::NativeErrToNdk(errCode);
}

int OH_Preferences_Delete(OH_Preferences *preference, const char *key)
{
    auto preferencesImpl = GetPreferencesImpl(preference);
    if (preferencesImpl == nullptr || key == nullptr) {
        LOG_ERROR("delete failed, preference is null: %{public}d, key is null: %{public}d",
            (preferencesImpl == nullptr), (key == nullptr));
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    std::shared_ptr<OHOS::NativePreferences::Preferences> nativePreferences = preferencesImpl->GetNativePreferences();
    if (nativePreferences == nullptr) {
        LOG_ERROR("preference not open yet");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    int errCode = nativePreferences->Delete(key);
    if (errCode != OHOS::NativePreferences::E_OK) {
        LOG_ERROR("preference delete value failed");
    }
    return ConvertorErrorCode::NativeErrToNdk(errCode);
}

int OH_Preferences_RegisterDataObserver(OH_Preferences *preference, void *context,
    const OH_PreferencesDataObserver *observer, const char *keys[], uint32_t keyCount)
{
    auto preferencesImpl = GetPreferencesImpl(preference);
    if (preferencesImpl == nullptr || observer == nullptr) {
        LOG_ERROR("register failed, invalid agrs, preference is null ? %{public}d, observer is null ? %{public}d",
            (preferencesImpl == nullptr), (observer == nullptr));
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (keyCount == 0) {
        return preferencesImpl->RegisterDataObserver(observer, context);
    }
    std::vector<std::string> keysVec;
    for (uint32_t i = 0; i < keyCount; i++) {
        keysVec.push_back(keys[i]);
    }
    
    return preferencesImpl->RegisterDataObserver(observer, context, keysVec);
}

int OH_Preferences_UnregisterDataObserver(OH_Preferences *preference, void *context,
    const OH_PreferencesDataObserver *observer, const char *keys[], uint32_t keyCount)
{
    auto preferencesImpl = GetPreferencesImpl(preference);
    if (preferencesImpl == nullptr || observer == nullptr) {
        LOG_ERROR("unregister failed, invalid agrs, preference is null ? %{public}d, observer is null ? %{public}d",
            (preferencesImpl == nullptr), (observer == nullptr));
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (keyCount == 0) {
        return preferencesImpl->UnRegisterDataObserver(observer);
    }
    std::vector<std::string> keysVec;
    for (uint32_t i = 0; i < keyCount; i++) {
        keysVec.push_back(keys[i]);
    }
    return preferencesImpl->UnRegisterDataObserver(observer, keysVec);
}

int OH_PreferencesImpl::RegisterDataObserver(
    const OH_PreferencesDataObserver *observer, void *context, const std::vector<std::string> &keys)
{
    std::unique_lock<std::shared_mutex> writeLock(obsMutex_);

    auto ndkObserver = std::make_shared<NDKPreferencesObserver>(observer, context);
    int errCode = preferences_->RegisterDataObserver(ndkObserver, keys);
    if (errCode != OHOS::NativePreferences::E_OK) {
        LOG_ERROR("register failed");
    } else {
        dataObservers_.emplace_back(std::move(ndkObserver));
    }
    return ConvertorErrorCode::NativeErrToNdk(errCode);
}

NDKPreferencesObserver::NDKPreferencesObserver(const OH_PreferencesDataObserver *observer, void *context)
    : dataObserver_(observer), context_(context) {}

void NDKPreferencesObserver::OnChange(const std::map<std::string, OHOS::NativePreferences::PreferencesValue> &records)
{
    auto count = records.size();
    if (count == 0) {
        return;
    }
    OH_PreferencesPair *pairs = new OH_PreferencesPair[count];
    if (pairs == nullptr) {
        LOG_ERROR("malloc pairs failed when on change, count: %{public}u, errno:%{public}d", count, errno);
        return;
    }
    int i = 0;
    for (const auto &[key, value] : records) {
        OH_PreferencesValueImpl *valueImpl = new OH_PreferencesValueImpl();
        if (value.IsInt()) {
            valueImpl->type_ = Preference_ValueType::TYPE_INT;
            valueImpl->value_ = value;
        } else if (value.IsBool()) {
            valueImpl->type_ = Preference_ValueType::TYPE_BOOL;
            valueImpl->value_ = value;
        } else if (value.IsString()) {
            valueImpl->type_ = Preference_ValueType::TYPE_STRING;
            valueImpl->value_ = value;
        } else {
            valueImpl->type_ = Preference_ValueType::TYPE_NULL;
        }
        pairs[i++] = OH_PreferencesPair { key.c_str(), valueImpl };
    }
    (*dataObserver_)(context_, pairs, count);
    for (size_t i = 0; i < count; i++) {
        delete pairs[i].value;
    }
    delete []pairs;
}

void NDKPreferencesObserver::OnChange(const std::string &key)
{
}

int OH_PreferencesImpl::UnRegisterDataObserver(const OH_PreferencesDataObserver *observer,
    const std::vector<std::string> &keys)
{
    std::unique_lock<std::shared_mutex> writeLock(obsMutex_);
    for (size_t i = 0; i < dataObservers_.size(); i++) {
        if (!(*dataObservers_[i] == observer)) {
            i++;
            continue;
        }
        int errCode = preferences_->UnRegisterDataObserver(dataObservers_[i], keys);
        if (errCode != OHOS::NativePreferences::E_OK) {
            LOG_ERROR("un register observer failed");
            return ConvertorErrorCode::NativeErrToNdk(errCode);
        }
    }
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

bool NDKPreferencesObserver::operator==(const OH_PreferencesDataObserver *other)
{
    if (other == nullptr) {
        return false;
    }
    return  &other == &dataObserver_;
}
