/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "preferences_enhance_impl.h"

#include <cinttypes>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <sstream>
#include <thread>

#include "executor_pool.h"
#include "preferences_file_operation.h"
#include "log_print.h"
#include "preferences_observer_stub.h"
#include "preferences_value.h"
#include "preferences_value_parcel.h"

namespace OHOS {
namespace NativePreferences {

PreferencesEnhanceImpl::PreferencesEnhanceImpl(const Options &options): PreferencesBase(options)
{
}

PreferencesEnhanceImpl::~PreferencesEnhanceImpl()
{
    std::unique_lock<std::shared_mutex> writeLock(dbMutex_);
    db_ = nullptr;
}

int PreferencesEnhanceImpl::Init()
{
    std::unique_lock<std::shared_mutex> writeLock(dbMutex_);
    db_ = std::make_shared<PreferencesDb>();
    return db_->Init(options_.filePath, options_.bundleName);
}

PreferencesValue PreferencesEnhanceImpl::Get(const std::string &key, const PreferencesValue &defValue)
{
    if (CheckKey(key) != E_OK) {
        return defValue;
    }
    std::shared_lock<std::shared_mutex> autoLock(dbMutex_);
    if (db_ == nullptr) {
        LOG_ERROR("PreferencesEnhanceImpl:Get failed, db has been closed.");
        return defValue;
    }

    std::vector<uint8_t> oriKey(key.begin(), key.end());
    std::vector<uint8_t> oriValue;
    int errCode = db_->Get(oriKey, oriValue);
    if (errCode != E_OK) {
        LOG_ERROR("get key failed, errCode=%{public}d", errCode);
        return defValue;
    }
    auto item = PreferencesValueParcel::UnmarshallingPreferenceValue(oriValue);
    if (item.first != E_OK) {
        LOG_ERROR("get key failed, errCode=%{public}d", errCode);
        return defValue;
    }
    return item.second;
}

bool PreferencesEnhanceImpl::HasKey(const std::string &key)
{
    if (CheckKey(key) != E_OK) {
        return false;
    }
    std::shared_lock<std::shared_mutex> autoLock(dbMutex_);
    if (db_ == nullptr) {
        LOG_ERROR("PreferencesEnhanceImpl:HasKey failed, db has been closed.");
        return E_ERROR;
    }

    std::vector<uint8_t> oriKey(key.begin(), key.end());
    std::vector<uint8_t> oriValue;
    int errCode = db_->Get(oriKey, oriValue);
    if (errCode != E_OK) {
        LOG_ERROR("get key failed, errCode=%{public}d", errCode);
        return false;
    }
    return true;
}

int PreferencesEnhanceImpl::Put(const std::string &key, const PreferencesValue &value)
{
    int errCode = CheckKey(key);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = CheckValue(value);
    if (errCode != E_OK) {
        return errCode;
    }
    std::unique_lock<std::shared_mutex> writeLock(dbMutex_);
    if (db_ == nullptr) {
        LOG_ERROR("PreferencesEnhanceImpl:Put failed, db has been closed.");
        return E_ERROR;
    }

    std::vector<uint8_t> oriValue;
    uint32_t oriValueLen = PreferencesValueParcel::CalSize(value);
    oriValue.resize(oriValueLen);
    errCode = PreferencesValueParcel::MarshallingPreferenceValue(value, oriValue);
    if (errCode != E_OK) {
        LOG_ERROR("marshalling value failed, errCode=%{public}d", errCode);
        return errCode;
    }
    std::vector<uint8_t> oriKey(key.begin(), key.end());
    errCode = db_->Put(oriKey, oriValue);
    if (errCode != E_OK) {
        LOG_ERROR("put data failed, errCode=%{public}d", errCode);
        return errCode;
    }

    ExecutorPool::Task task = [pref = shared_from_this(), key, value] {
        PreferencesEnhanceImpl::NotifyPreferencesObserver(pref, key, value);
    };
    executorPool_.Execute(std::move(task));
    return E_OK;
}

int PreferencesEnhanceImpl::Delete(const std::string &key)
{
    int errCode = CheckKey(key);
    if (errCode != E_OK) {
        return errCode;
    }
    std::unique_lock<std::shared_mutex> writeLock(dbMutex_);
    if (db_ == nullptr) {
        LOG_ERROR("PreferencesEnhanceImpl:Delete failed, db has been closed.");
        return E_ERROR;
    }

    std::vector<uint8_t> oriKey(key.begin(), key.end());
    errCode = db_->Delete(oriKey);
    if (errCode != E_OK) {
        LOG_ERROR("delete data failed, errCode=%{public}d", errCode);
        return errCode;
    }

    PreferencesValue value;
    ExecutorPool::Task task = [pref = shared_from_this(), key, value] {
        PreferencesEnhanceImpl::NotifyPreferencesObserver(pref, key, value);
    };
    executorPool_.Execute(std::move(task));
    return E_OK;
}

std::map<std::string, PreferencesValue> PreferencesEnhanceImpl::GetAll()
{
    std::shared_lock<std::shared_mutex> autoLock(dbMutex_);
    if (db_ == nullptr) {
        LOG_ERROR("PreferencesEnhanceImpl:GetAll failed, db has been closed.");
        return {};
    }

    std::map<std::string, PreferencesValue> result;
    std::list<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> data;
    int errCode = db_->GetAll(data);
    if (errCode != E_OK) {
        LOG_ERROR("get all failed, errCode=%{public}d", errCode);
        return {};
    }
    for (auto it = data.begin(); it != data.end(); it++) {
        std::string key(it->first.begin(), it->first.end());
        auto item = PreferencesValueParcel::UnmarshallingPreferenceValue(it->second);
        result.insert({key, item.second});
        if (item.first != E_OK) {
            LOG_ERROR("get key failed, errCode=%{public}d", errCode);
            return {};
        }
    }
    return result;
}

void PreferencesEnhanceImpl::NotifyPreferencesObserver(std::shared_ptr<PreferencesEnhanceImpl> pref,
    const std::string &key, const PreferencesValue &value)
{
    std::shared_lock<std::shared_mutex> readLock(pref->mapSharedMutex_);
    LOG_DEBUG("notify observer size:%{public}zu", pref->dataObserversMap_.size());
    for (const auto &[weakPrt, keys] : pref->dataObserversMap_) {
        std::map<std::string, PreferencesValue> records = {{key, value}};
        if (std::shared_ptr<PreferencesObserver> sharedPtr = weakPrt.lock()) {
            LOG_DEBUG("dataChange observer call, resultSize:%{public}zu", records.size());
            sharedPtr->OnChange(records);
        }
    }
    auto dataObsMgrClient = DataObsMgrClient::GetInstance();
    for (auto it = pref->localObservers_.begin(); it != pref->localObservers_.end(); ++it) {
        std::weak_ptr<PreferencesObserver> weakPreferencesObserver = *it;
        if (std::shared_ptr<PreferencesObserver> sharedPreferencesObserver = weakPreferencesObserver.lock()) {
            sharedPreferencesObserver->OnChange(key);
        }
    }
    if (dataObsMgrClient != nullptr) {
        dataObsMgrClient->NotifyChange(pref->MakeUri(key));
    }
}

int PreferencesEnhanceImpl::Clear()
{
    std::unique_lock<std::shared_mutex> writeLock(dbMutex_);
    LOG_INFO("Clear called, file: %{public}s", ExtractFileName(options_.filePath).c_str());
    if (db_ == nullptr) {
        LOG_ERROR("PreferencesEnhanceImpl:Clear failed, db has been closed.");
        return E_ERROR;
    }

    int errCode = db_->DropCollection();
    if (errCode != E_OK) {
        LOG_ERROR("drop collection failed when clear, errCode=%{public}d", errCode);
        return errCode;
    }
    errCode = db_->CreateCollection();
    if (errCode != E_OK) {
        LOG_ERROR("create collection failed when clear, errCode=%{public}d", errCode);
    }
    return errCode;
}

int PreferencesEnhanceImpl::CloseDb()
{
    std::unique_lock<std::shared_mutex> writeLock(dbMutex_);
    if (db_ == nullptr) {
        LOG_WARN("PreferencesEnhanceImpl:CloseDb failed, db has been closed, no need to close again.");
        return E_OK;
    }
    int errCode = db_->CloseDb();
    if (errCode != E_OK) {
        LOG_ERROR("PreferencesEnhanceImpl:CloseDb failed.");
        return errCode;
    }
    db_ = nullptr;
    return E_OK;
}

} // End of namespace NativePreferences
} // End of namespace OHOS
