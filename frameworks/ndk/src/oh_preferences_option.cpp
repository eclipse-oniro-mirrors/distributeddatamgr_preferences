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

#include "oh_preferences_option.h"

#include "log_print.h"
#include "oh_convertor.h"
#include "oh_preferences_impl.h"
#include "oh_preferences_err_code.h"
#include "preferences_helper.h"

using namespace OHOS::PreferencesNdk;

int OH_PreferencesOption::SetFileName(const std::string &str)
{
    std::unique_lock<std::shared_mutex> writeLock(opMutex_);
    if (str.empty()) {
        LOG_ERROR("Set file path failed, str is empty");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    fileName = str;
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

void OH_PreferencesOption::SetBundleName(const std::string &str)
{
    std::unique_lock<std::shared_mutex> writeLock(opMutex_);
    bundleName = str;
}

void OH_PreferencesOption::SetDataGroupId(const std::string &str)
{
    std::unique_lock<std::shared_mutex> writeLock(opMutex_);
    dataGroupId = str;
}

void OH_PreferencesOption::SetStorageType(const Preferences_StorageType &type)
{
    std::unique_lock<std::shared_mutex> writeLock(opMutex_);
    storageType = type;
}

Preferences_StorageType OH_PreferencesOption::GetStorageType()
{
    std::shared_lock<std::shared_mutex> readLock(opMutex_);
    return storageType;
}

std::string OH_PreferencesOption::GetFileName()
{
    std::shared_lock<std::shared_mutex> readLock(opMutex_);
    return fileName;
}

std::string OH_PreferencesOption::GetBundleName()
{
    std::shared_lock<std::shared_mutex> readLock(opMutex_);
    return bundleName;
}

std::string OH_PreferencesOption::GetDataGroupId()
{
    std::shared_lock<std::shared_mutex> readLock(opMutex_);
    return dataGroupId;
}

OH_PreferencesOption* OH_PreferencesOption_Create(void)
{
    OH_PreferencesOption* option = new (std::nothrow) OH_PreferencesOption();
    if (option == nullptr) {
        LOG_ERROR("new option object failed");
        return nullptr;
    }
    option->cid = PreferencesNdkStructId::PREFERENCES_OH_OPTION_CID;
    if (!OHOS::NativePreferences::PreferencesHelper::IsStorageTypeSupported(
        OHConvertor::NdkStorageTypeToNative(Preferences_StorageType::PREFERENCES_STORAGE_GSKV))) {
        option->SetStorageType(Preferences_StorageType::PREFERENCES_STORAGE_XML);
    }
    return option;
}

int OH_PreferencesOption_SetFileName(OH_PreferencesOption *option, const char *fileName)
{
    if (option == nullptr || fileName == nullptr ||
        !NDKPreferencesUtils::PreferencesStructValidCheck(
            option->cid, PreferencesNdkStructId::PREFERENCES_OH_OPTION_CID)) {
        LOG_ERROR("set option's file path failed, option is null: %{public}d, fileName is null: %{public}d, "
            "err: %{public}d", (option == nullptr), (fileName == nullptr),
            OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    return option->SetFileName(std::string(fileName));
}

int OH_PreferencesOption_SetBundleName(OH_PreferencesOption *option, const char *bundleName)
{
    if (option == nullptr || bundleName == nullptr ||
        !NDKPreferencesUtils::PreferencesStructValidCheck(
            option->cid, PreferencesNdkStructId::PREFERENCES_OH_OPTION_CID)) {
        LOG_ERROR("set option's bundleName failed, option is null: %{public}d, "
            "bundleName is null: %{public}d, errCode: %{public}d", (option == nullptr),
            (bundleName == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    option->SetBundleName(std::string(bundleName));
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesOption_SetDataGroupId(OH_PreferencesOption *option, const char *dataGroupId)
{
    if (option == nullptr || dataGroupId == nullptr ||
        !NDKPreferencesUtils::PreferencesStructValidCheck(
            option->cid, PreferencesNdkStructId::PREFERENCES_OH_OPTION_CID)) {
        LOG_ERROR("set option's dataGroupId failed, option is null: %{public}d, "
            "dataGroupId is null: %{public}d, errCode: %{public}d", (option == nullptr),
            (dataGroupId == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    option->SetDataGroupId(std::string(dataGroupId));
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesOption_SetStorageType(OH_PreferencesOption *option, Preferences_StorageType type)
{
    if (option == nullptr || !NDKPreferencesUtils::PreferencesStructValidCheck(
        option->cid, PreferencesNdkStructId::PREFERENCES_OH_OPTION_CID)) {
        LOG_ERROR("set option's storage type failed, option is null: %{public}d", (option == nullptr));
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (type < Preferences_StorageType::PREFERENCES_STORAGE_XML ||
        type > Preferences_StorageType::PREFERENCES_STORAGE_GSKV) {
        LOG_ERROR("set option's storage type failed, type invalid: %{public}d", static_cast<int>(type));
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    option->SetStorageType(type);
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesOption_Destroy(OH_PreferencesOption* option)
{
    if (option == nullptr ||
        !NDKPreferencesUtils::PreferencesStructValidCheck(
            option->cid, PreferencesNdkStructId::PREFERENCES_OH_OPTION_CID)) {
        LOG_ERROR("destroy option failed, option is null: %{public}d, errCode: %{public}d",
            (option == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    delete option;
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}
