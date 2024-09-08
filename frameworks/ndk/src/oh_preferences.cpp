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
#include "securec.h"

using namespace OHOS::PreferencesNdk;

OH_PreferencesImpl::OH_PreferencesImpl
    (std::shared_ptr<OHOS::NativePreferences::Preferences> preferences) : preferences_(preferences)
{
}

bool NDKPreferencesUtils::PreferencesStructValidCheck(int64_t originCid, int64_t targetCid)
{
    if (originCid != targetCid) {
        LOG_ERROR("cid check failed, ori cid: %{public}ld, target cid: %{public}ld", static_cast<long>(originCid),
            static_cast<long>(targetCid));
        return false;
    }
    return true;
}

static int CreateDirectoryRecursively(const std::string &path)
{
    std::string::size_type pos = path.find_last_of('/');
    if (pos == std::string::npos || path.front() != '/' || path.back() == '/') {
        LOG_ERROR("path can not be relative path.");
        return OH_Preferences_ErrCode::PREFERENCES_OK;
    }
    std::string dir = path.substr(0, pos);

    std::string tempDirectory = dir;
    std::vector<std::string> directories;

    pos = tempDirectory.find('/');
    while (pos != std::string::npos) {
        std::string directory = tempDirectory.substr(0, pos);
        if (!directory.empty()) {
            directories.push_back(directory);
        }
        tempDirectory = tempDirectory.substr(pos + 1);
        pos = tempDirectory.find('/');
    }
    directories.push_back(tempDirectory);

    std::string databaseDirectory;
    for (const std::string& directory : directories) {
        databaseDirectory = databaseDirectory + "/" + directory;
        if (OHOS::NativePreferences::Access(databaseDirectory.c_str()) != F_OK) {
            if (OHOS::NativePreferences::Mkdir(databaseDirectory)) {
                LOG_ERROR("failed to mkdir errno[%{public}d] %{public}s", errno, databaseDirectory.c_str());
                return PREFERENCES_ERROR_STORAGE;
            }
        }
    }

    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

OH_Preferences *OH_Preferences_Open(OH_PreferencesOption *options, int *errCode)
{
    int err = OH_Preferences_ErrCode::PREFERENCES_OK;
    if (options == nullptr || options->filePath.empty() ||
        !NDKPreferencesUtils::PreferencesStructValidCheck(
            options->cid, PreferencesNdkStructId::PREFERENCES_OH_OPTION_CID) ||
        errCode == nullptr) {
        LOG_ERROR("open preference cfg error, options is null: %{public}d, filePath is null: %{public}d, "
            "errCode is null: %{public}d, err:%{public}d",
            (options == nullptr), (options == nullptr) ? 1 : options->filePath.empty(), (errCode == nullptr),
            OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        if (errCode != nullptr) {
            *errCode = OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
        }
        return nullptr;
    }

    std::string fileStr = options->GetFilePath();
    err = CreateDirectoryRecursively(fileStr);
    if (err != OH_Preferences_ErrCode::PREFERENCES_OK) {
        *errCode = err;
        return nullptr;
    }

    OHOS::NativePreferences::Options nativeOptions(fileStr, options->GetBundleName(),
        options->GetDataGroupId(), true);

    std::shared_ptr<OHOS::NativePreferences::Preferences> innerPreferences=
        OHOS::NativePreferences::PreferencesHelper::GetPreferences(nativeOptions, err);
    err = ConvertorErrorCode::NativeErrToNdk(err);
    *errCode = err;
    if (innerPreferences== nullptr || err != OH_Preferences_ErrCode::PREFERENCES_OK) {
        LOG_ERROR("Get native Preferences failed: %{public}s, errcode: %{public}d",
            OHOS::NativePreferences::ExtractFileName(nativeOptions.filePath).c_str(), err);
        return nullptr;
    }
    OH_PreferencesImpl *preferenceImpl = new (std::nothrow) OH_PreferencesImpl(innerPreferences);
    if (preferenceImpl == nullptr) {
        LOG_ERROR("new impl object failed");
        *errCode = OH_Preferences_ErrCode::PREFERENCES_ERROR_MALLOC;
        return nullptr;
    }
    preferenceImpl->SetPreferencesStoreFilePath(options->filePath);
    preferenceImpl->cid = PreferencesNdkStructId::PREFERENCES_OH_PREFERENCES_CID;
    return static_cast<OH_Preferences *>(preferenceImpl);
}

static OH_PreferencesImpl *GetPreferencesImpl(OH_Preferences *preference)
{
    if (preference == nullptr ||
        !NDKPreferencesUtils::PreferencesStructValidCheck(
            preference->cid, PreferencesNdkStructId::PREFERENCES_OH_PREFERENCES_CID)) {
        LOG_ERROR("preference invalid, is null: %{public}d", preference == nullptr);
        return nullptr;
    }
    return static_cast<OH_PreferencesImpl *>(preference);
}

static std::shared_ptr<OHOS::NativePreferences::Preferences> GetNativePreferencesFromOH(OH_Preferences *preference)
{
    auto preferencesImpl = GetPreferencesImpl(preference);
    if (preferencesImpl == nullptr ||
        !NDKPreferencesUtils::PreferencesStructValidCheck(
            preference->cid, PreferencesNdkStructId::PREFERENCES_OH_PREFERENCES_CID)) {
        LOG_ERROR("preferences is null: %{public}d when get native preferences from ohPreferences",
            (preferencesImpl == nullptr));
        return nullptr;
    }
    std::shared_ptr<OHOS::NativePreferences::Preferences> innerPreferences= preferencesImpl->GetNativePreferences();
    if (innerPreferences== nullptr) {
        LOG_ERROR("preference not open yet");
        return nullptr;
    }
    return innerPreferences;
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
    std::shared_ptr<OHOS::NativePreferences::Preferences> innerPreferences= preferencesImpl->GetNativePreferences();
    if (innerPreferences== nullptr) {
        LOG_ERROR("preference not open yet");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    innerPreferences->FlushSync();

    int errCode = OHOS::NativePreferences::PreferencesHelper::RemovePreferencesFromCache(
        preferencesImpl->GetPreferencesStoreFilePath());
    if (errCode != OHOS::NativePreferences::E_OK) {
        LOG_ERROR("preference close failed: %{public}d", errCode);
        return ConvertorErrorCode::NativeErrToNdk(errCode);
    }
    delete preferencesImpl;
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_Preferences_GetInt(OH_Preferences *preference, const char *key, int *value)
{
    std::shared_ptr<OHOS::NativePreferences::Preferences> innerPreferences= GetNativePreferencesFromOH(preference);
    if (innerPreferences== nullptr || key == nullptr || value == nullptr) {
        LOG_ERROR("get int failed, preference not open yet: %{public}d, key is null: %{public}d, "
            "value is null: %{public}d, err: %{public}d", (innerPreferences== nullptr), (key == nullptr),
            (value == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    auto res = innerPreferences->GetValue(key, OHOS::NativePreferences::PreferencesValue());
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
    std::shared_ptr<OHOS::NativePreferences::Preferences> innerPreferences= GetNativePreferencesFromOH(preference);
    if (innerPreferences== nullptr || key == nullptr || value == nullptr || valueLen == nullptr) {
        LOG_ERROR("get str failed, preference not open yet: %{public}d, key is null: %{public}d, "
            "value is null: %{public}d, valueLen is null: %{public}d, err: %{public}d",
            (innerPreferences== nullptr), (key == nullptr), (value == nullptr), (valueLen == nullptr),
            OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    auto res = innerPreferences->GetValue(key, OHOS::NativePreferences::PreferencesValue());
    if (res.second.IsString()) {
        std::string str = (std::string)(res.second);
        size_t strLen = str.size();
        if (strLen >= SIZE_MAX) {
            LOG_ERROR(" string length overlimit: %{public}zu", strLen);
            return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
        }
        void *ptr = malloc(strLen + 1); // free by caller
        if (ptr == nullptr) {
            LOG_ERROR("malloc failed when get string, errno: %{public}d", errno);
            return OH_Preferences_ErrCode::PREFERENCES_ERROR_MALLOC;
        }
        *value = (char *)ptr;
        int sysErr = memset_s(*value, (strLen + 1), 0, (strLen + 1));
        if (sysErr != EOK) {
            LOG_ERROR("memset failed when get string, errCode: %{public}d", sysErr);
        }
        sysErr = memcpy_s(*value, strLen, str.c_str(), strLen);
        if (sysErr != EOK) {
            LOG_ERROR("memcpy failed when get string, errCode: %{public}d", sysErr);
            free(ptr);
            return OH_Preferences_ErrCode::PREFERENCES_ERROR_MALLOC;
        }
        *valueLen = strLen + 1;
    } else {
        LOG_ERROR("Get string failed, value's type is not string, err: %{public}d", res.first);
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
    std::shared_ptr<OHOS::NativePreferences::Preferences> innerPreferences= GetNativePreferencesFromOH(preference);
    if (innerPreferences== nullptr || key == nullptr || value == nullptr) {
        LOG_ERROR("get bool failed, preference not open yet: %{public}d, key is null: %{public}d, "
            "value is null: %{public}d, err: %{public}d", (innerPreferences== nullptr), (key == nullptr),
            (value == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    auto res = innerPreferences->GetValue(key, OHOS::NativePreferences::PreferencesValue());
    if (res.second.IsBool()) {
        *value = (bool)(res.second);
    } else {
        LOG_ERROR("Get bool failed, value's type is not bool, err: %{public}d", res.first);
    }

    return ConvertorErrorCode::NativeErrToNdk(res.first);
}

int OH_Preferences_SetInt(OH_Preferences *preference, const char *key, int value)
{
    std::shared_ptr<OHOS::NativePreferences::Preferences> innerPreferences= GetNativePreferencesFromOH(preference);
    if (innerPreferences== nullptr || key == nullptr) {
        LOG_ERROR("set int failed, preference not open yet: %{public}d, key is null: %{public}d, err: %{public}d",
            (innerPreferences== nullptr), (key == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    int errCode = innerPreferences->PutInt(key, value);
    if (errCode != OHOS::NativePreferences::E_OK) {
        LOG_ERROR("preference put int failed, err: %{public}d", errCode);
    }
    return ConvertorErrorCode::NativeErrToNdk(errCode);
}

int OH_Preferences_SetBool(OH_Preferences *preference, const char *key, bool value)
{
    std::shared_ptr<OHOS::NativePreferences::Preferences> innerPreferences= GetNativePreferencesFromOH(preference);
    if (innerPreferences== nullptr || key == nullptr) {
        LOG_ERROR("set bool failed, preference not open yet: %{public}d, key is null: %{public}d, err: %{public}d",
            (innerPreferences== nullptr), (key == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    int errCode = innerPreferences->PutBool(key, value);
    if (errCode != OHOS::NativePreferences::E_OK) {
        LOG_ERROR("preference put bool failed, err: %{public}d", errCode);
    }
    return ConvertorErrorCode::NativeErrToNdk(errCode);
}

int OH_Preferences_SetString(OH_Preferences *preference, const char *key, const char *value)
{
    std::shared_ptr<OHOS::NativePreferences::Preferences> innerPreferences= GetNativePreferencesFromOH(preference);
    if (innerPreferences== nullptr || key == nullptr || value == nullptr) {
        LOG_ERROR("set str failed, preference not open yet: %{public}d, key is null: %{public}d, "
            "value is null: %{public}d, err: %{public}d", (innerPreferences== nullptr), (key == nullptr),
            (value == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    int errCode = innerPreferences->PutString(key, value);
    if (errCode != OHOS::NativePreferences::E_OK) {
        LOG_ERROR("preference put string failed, err: %{public}d", errCode);
    }
    return ConvertorErrorCode::NativeErrToNdk(errCode);
}

int OH_Preferences_Delete(OH_Preferences *preference, const char *key)
{
    std::shared_ptr<OHOS::NativePreferences::Preferences> innerPreferences= GetNativePreferencesFromOH(preference);
    if (innerPreferences== nullptr || key == nullptr) {
        LOG_ERROR("delete failed, preference not open yet: %{public}d, key is null: %{public}d, err: %{public}d",
            (innerPreferences== nullptr), (key == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    int errCode = innerPreferences->Delete(key);
    if (errCode != OHOS::NativePreferences::E_OK) {
        LOG_ERROR("preference delete value failed, err: %{public}d", errCode);
    }
    return ConvertorErrorCode::NativeErrToNdk(errCode);
}

int OH_Preferences_RegisterDataObserver(OH_Preferences *preference, void *context,
    const OH_PreferencesDataObserver *observer, const char *keys[], uint32_t keyCount)
{
    auto preferencesImpl = GetPreferencesImpl(preference);
    if (preferencesImpl == nullptr || observer == nullptr || keys == nullptr) {
        LOG_ERROR("register failed, sp is null ? %{public}d, obs is null ? %{public}d, "
            "keys is null: %{public}d, err: %{public}d", (preferencesImpl == nullptr), (observer == nullptr),
            (keys == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    std::vector<std::string> keysVec;
    for (uint32_t i = 0; i < keyCount; i++) {
        keysVec.push_back(keys[i]);
    }
    
    return ConvertorErrorCode::NativeErrToNdk(preferencesImpl->RegisterDataObserver(observer, context, keysVec));
}

int OH_Preferences_UnregisterDataObserver(OH_Preferences *preference, void *context,
    const OH_PreferencesDataObserver *observer, const char *keys[], uint32_t keyCount)
{
    auto preferencesImpl = GetPreferencesImpl(preference);
    if (preferencesImpl == nullptr || observer == nullptr || keys == nullptr) {
        LOG_ERROR("unregister failed, sp is null ? %{public}d, obs is null ? %{public}d, "
            "keys is null: %{public}d, err: %{public}d", (preferencesImpl == nullptr), (observer == nullptr),
            (keys == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    std::vector<std::string> keysVec;
    keysVec.resize(keyCount);
    for (uint32_t i = 0; i < keyCount; i++) {
        keysVec.push_back(keys[i]);
    }
    return ConvertorErrorCode::NativeErrToNdk(preferencesImpl->UnregisterDataObserver(observer, context, keysVec));
}

int OH_PreferencesImpl::RegisterDataObserver(
    const OH_PreferencesDataObserver *observer, void *context, const std::vector<std::string> &keys)
{
    std::unique_lock<std::shared_mutex> writeLock(obsMutex_);

    auto ndkObserver = std::make_shared<NDKPreferencesObserver>(observer, context);
    int errCode = preferences_->RegisterDataObserver(ndkObserver, keys);
    if (errCode != OHOS::NativePreferences::E_OK) {
        LOG_ERROR("register failed, err: %{public}d", errCode);
    } else {
        dataObservers_.emplace_back(std::make_pair(std::move(ndkObserver), context));
    }
    return ConvertorErrorCode::NativeErrToNdk(errCode);
}

NDKPreferencesObserver::NDKPreferencesObserver(const OH_PreferencesDataObserver *observer, void *context)
    : dataObserver_(observer), context_(context) {}

inline void FreePairValue(OH_PreferencesPair *pairs, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        delete pairs[i].value;
    }
}

void NDKPreferencesObserver::OnChange(const std::map<std::string, OHOS::NativePreferences::PreferencesValue> &records)
{
    if (dataObserver_ == nullptr) {
        LOG_ERROR("failed to trigger change, data observer is null");
        return;
    }
    auto count = records.size();
    if (count == 0) {
        return;
    }
    OH_PreferencesPair *pairs = new (std::nothrow) OH_PreferencesPair[count];
    if (pairs == nullptr) {
        LOG_ERROR("malloc pairs failed when on change, count: %{public}d, errno:%{public}d", static_cast<int>(count),
            errno);
        return;
    }
    int i = 0;
    for (const auto &[key, value] : records) {
        OH_PreferencesValueImpl *valueImpl = new (std::nothrow) OH_PreferencesValueImpl();
        if (valueImpl == nullptr) {
            LOG_ERROR("new value object failed");
            FreePairValue(pairs, i);
            delete []pairs;
        }
        valueImpl->cid = PreferencesNdkStructId::PREFERENCES_OH_VALUE_CID;
        valueImpl->value_ = value;
        pairs[i++] = OH_PreferencesPair { PreferencesNdkStructId::PREFERENCES_OH_PAIR_CID, key.c_str(),
            static_cast<OH_PreferencesValue *>(valueImpl), count};
    }
    (*dataObserver_)(context_, pairs, count);
    FreePairValue(pairs, count);
    delete []pairs;
}

void NDKPreferencesObserver::OnChange(const std::string &key)
{
}

int OH_PreferencesImpl::UnregisterDataObserver(const OH_PreferencesDataObserver *observer, void *context,
    const std::vector<std::string> &keys)
{
    std::unique_lock<std::shared_mutex> writeLock(obsMutex_);
    for (size_t i = 0; i < dataObservers_.size(); i++) {
        if (!(*dataObservers_[i].first == observer) || dataObservers_[i].second != context) {
            continue;
        }
        int errCode = preferences_->UnRegisterDataObserver(dataObservers_[i].first, keys);
        if (errCode != OHOS::NativePreferences::E_OK) {
            LOG_ERROR("un register observer failed, err: %{public}d", errCode);
            return ConvertorErrorCode::NativeErrToNdk(errCode);
        }
        if (keys.empty()) {
            dataObservers_[i] = { nullptr, nullptr };
            dataObservers_.erase(dataObservers_.begin() + i);
        }
    }
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

bool NDKPreferencesObserver::operator==(const OH_PreferencesDataObserver *other)
{
    if (other == nullptr) {
        return false;
    }
    return  other == dataObserver_;
}
