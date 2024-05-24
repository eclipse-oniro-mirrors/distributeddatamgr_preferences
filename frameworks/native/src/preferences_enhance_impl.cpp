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
    return db_->Init(options_.filePath);
}

PreferencesValue PreferencesEnhanceImpl::Get(const std::string &key, const PreferencesValue &defValue)
{
    if (CheckKey(key) != E_OK) {
        return defValue;
    }
    std::shared_lock<std::shared_mutex> autoLock(dbMutex_);
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
    ExecutorPool::Task task = std::bind(PreferencesEnhanceImpl::NotifyPreferencesObserver, shared_from_this(), key,
        value);
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
    std::vector<uint8_t> oriKey(key.begin(), key.end());
    errCode = db_->Delete(oriKey);
    if (errCode != E_OK) {
        LOG_ERROR("delete data failed, errCode=%{public}d", errCode);
        return errCode;
    }
    PreferencesValue value;
    ExecutorPool::Task task = std::bind(PreferencesEnhanceImpl::NotifyPreferencesObserver, shared_from_this(), key,
        value);
    executorPool_.Execute(std::move(task));
    return E_OK;
}

std::map<std::string, PreferencesValue> PreferencesEnhanceImpl::GetAll()
{
    std::shared_lock<std::shared_mutex> autoLock(dbMutex_);
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
    std::lock_guard<std::mutex> lock(pref->observerMapMutex_);
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
} // End of namespace NativePreferences
} // End of namespace OHOS
