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

#include "preferences_impl.h"

#include <cinttypes>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <thread>
#include <chrono>
#include <cinttypes>

#include "executor_pool.h"
#include "log_print.h"
#include "preferences_xml_utils.h"
#include "preferences_file_operation.h"
#include "preferences_anonymous.h"
#include "preferences_dfx_adapter.h"
#include "preferences_utils.h"

namespace OHOS {
namespace NativePreferences {

using namespace std::chrono;

constexpr int32_t WAIT_TIME = 2;
constexpr int32_t TASK_EXEC_TIME = 100;
constexpr int32_t LOAD_XML_LOG_TIME = 1000;
PreferencesImpl::PreferencesImpl(const Options &options) : PreferencesBase(options)
{
    loaded_.store(false);
    isNeverUnlock_ = false;
    loadResult_= false;
    queue_ = std::make_shared<SafeBlockQueue<uint64_t>>(1);
    dataObsMgrClient_ = DataObsMgrClient::GetInstance();
    isActive_.store(true);
    isCleared_.store(false);
}

PreferencesImpl::~PreferencesImpl()
{
}

int PreferencesImpl::Init()
{
    if (!StartLoadFromDisk()) {
        return E_ERROR;
    }
    return E_OK;
}

bool PreferencesImpl::StartLoadFromDisk()
{
    std::lock_guard<std::mutex> lock(mutex_);
    loaded_.store(false);
    isNeverUnlock_ = false;
    loadResult_ = false;

    ExecutorPool::Task task = [pref = shared_from_this()] { PreferencesImpl::LoadFromDisk(pref); };
    return (executorPool_.Execute(std::move(task)) == ExecutorPool::INVALID_TASK_ID) ? false : true;
}

/* static */
void PreferencesImpl::LoadFromDisk(std::shared_ptr<PreferencesImpl> pref)
{
    if (pref->loaded_.load()) {
        return;
    }
    std::lock_guard<std::mutex> lock(pref->mutex_);
    if (!pref->loaded_.load()) {
        std::string::size_type pos = pref->options_.filePath.find_last_of('/');
        std::string filePath = pref->options_.filePath.substr(0, pos);
        if (Access(filePath) != 0) {
            pref->isNeverUnlock_ = true;
        }
        std::unordered_map<std::string, PreferencesValue> values;
        bool loadResult = pref->ReadSettingXml(values);
        if (!loadResult) {
            LOG_WARN("The settingXml %{public}s load failed.", ExtractFileName(pref->options_.filePath).c_str());
        } else {
            std::unique_lock<decltype(pref->cacheMutex_)> lock(pref->cacheMutex_);
            pref->valuesCache_ = std::move(values);
            pref->loadResult_ = true;
            pref->isNeverUnlock_ = false;
        }
        pref->loaded_.store(true);
        pref->cond_.notify_all();
    }
}

bool PreferencesImpl::ReloadFromDisk()
{
    if (loadResult_) {
        return false;
    }

    std::unique_lock<decltype(cacheMutex_)> lock(cacheMutex_);
    std::unordered_map<std::string, PreferencesValue> values = valuesCache_;
    bool loadResult = ReadSettingXml(values);
    LOG_WARN("The settingXml %{public}s reload result is %{public}d",
        ExtractFileName(options_.filePath).c_str(), loadResult);
    if (loadResult) {
        valuesCache_ = std::move(values);
        isNeverUnlock_ = false;
        loadResult_ = true;
        return true;
    }
    return false;
}

bool PreferencesImpl::PreLoad()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!loaded_.load()) {
        return true;
    }
    if (isNeverUnlock_ || (!isNeverUnlock_ && !loadResult_)) {
        if (Access(options_.filePath) == 0) {
            return ReloadFromDisk();
        }
    }
    return true;
}

void PreferencesImpl::AwaitLoadFile()
{
    if (loaded_.load()) {
        PreLoad();
        return;
    }
    std::unique_lock<std::mutex> lock(mutex_);
    if (!loaded_.load()) {
        cond_.wait_for(lock, std::chrono::seconds(WAIT_TIME), [this] { return loaded_.load(); });
    }

    if (!loaded_.load()) {
        LOG_ERROR("The settingXml %{public}s load timeout.", ExtractFileName(options_.filePath).c_str());
    }
}

PreferencesValue PreferencesImpl::Get(const std::string &key, const PreferencesValue &defValue)
{
    if (CheckKey(key) != E_OK) {
        return defValue;
    }

    AwaitLoadFile();
    IsClose(std::string(__FUNCTION__));

    std::shared_lock<decltype(cacheMutex_)> lock(cacheMutex_);
    if (!isCleared_.load()) {
        auto iter = valuesCache_.find(key);
        if (iter != valuesCache_.end()) {
            return iter->second;
        }
    }
    return defValue;
}

std::map<std::string, PreferencesValue> PreferencesImpl::GetAll()
{
    AwaitLoadFile();
    IsClose(std::string(__FUNCTION__));
    std::map<std::string, PreferencesValue> allDatas;
    std::shared_lock<decltype(cacheMutex_)> lock(cacheMutex_);
    if (!isCleared_.load()) {
        for (auto &it : valuesCache_) {
            allDatas.insert_or_assign(it.first, it.second);
        }
    }
    return allDatas;
}

static int64_t GetFileSize(const std::string &path)
{
    int64_t fileSize = -1;
    struct stat buffer;
    if (stat(path.c_str(), &buffer) == 0) {
        fileSize = static_cast<int64_t>(buffer.st_size);
    }
    return fileSize;
}

bool PreferencesImpl::ReadSettingXml(std::unordered_map<std::string, PreferencesValue> &conMap)
{
    auto begin = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    if (!PreferencesXmlUtils::ReadSettingXml(options_.filePath, options_.bundleName, conMap)) {
        return false;
    }
    auto end = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    if (end - begin > LOAD_XML_LOG_TIME) {
        LOG_ERROR("The settingXml %{public}s load time exceed 1s, file size:%{public}" PRId64 ".",
            ExtractFileName(options_.filePath).c_str(), GetFileSize(options_.filePath));
    }
    return true;
}

int PreferencesImpl::Close()
{
    isActive_.store(false);
    return E_OK;
}

bool PreferencesImpl::IsClose(const std::string &name)
{
    if (isActive_.load()) {
        return false;
    }

    LOG_WARN("file %{public}s is inactive.", ExtractFileName(options_.filePath).c_str());
    std::string operationMsg = " use after close.";
    ReportFaultParam reportParam = { "inactive object", options_.bundleName, NORMAL_DB,
        ExtractFileName(options_.filePath), E_OBJECT_NOT_ACTIVE, name + operationMsg };
    PreferencesDfxManager::ReportAbnormalOperation(reportParam, ReportedFaultBitMap::OBJECT_IS_NOT_ACTIVE);
    return true;
}

bool PreferencesImpl::HasKey(const std::string &key)
{
    if (CheckKey(key) != E_OK) {
        return false;
    }

    AwaitLoadFile();
    IsClose(std::string(__FUNCTION__));
    std::shared_lock<decltype(cacheMutex_)> lock(cacheMutex_);
    if (isCleared_.load()) {
        return false;
    }
    return valuesCache_.find(key) != valuesCache_.end();
}

int PreferencesImpl::Put(const std::string &key, const PreferencesValue &value)
{
    int errCode = CheckKey(key);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = CheckValue(value);
    if (errCode != E_OK) {
        return errCode;
    }
    AwaitLoadFile();
    IsClose(std::string(__FUNCTION__));

    std::unique_lock<decltype(cacheMutex_)> lock(cacheMutex_);
    if (isCleared_.load()) { // has cleared.
        for (auto &it : valuesCache_) {
            modifiedKeys_.emplace(it.first);
        }
        valuesCache_.clear();
        valuesCache_.insert_or_assign(key, value);
        modifiedKeys_.emplace(key);
        isCleared_.store(false);
    } else {
        auto iter = valuesCache_.find(key);
        if (iter != valuesCache_.end()) {
            PreferencesValue &val = iter->second;
            if (val == value) {
                return E_OK;
            }
        }
        valuesCache_.insert_or_assign(key, value);
        modifiedKeys_.emplace(key);
    }
    return E_OK;
}

int PreferencesImpl::Delete(const std::string &key)
{
    int errCode = CheckKey(key);
    if (errCode != E_OK) {
        return errCode;
    }
    AwaitLoadFile();
    IsClose(std::string(__FUNCTION__));
    std::unique_lock<decltype(cacheMutex_)> lock(cacheMutex_);
    if (isCleared_.load()) {
        return E_OK;
    }
    if (valuesCache_.find(key) != valuesCache_.end()) {
        valuesCache_.erase(key);
        modifiedKeys_.emplace(key);
    }
    return E_OK;
}

int PreferencesImpl::Clear()
{
    AwaitLoadFile();
    IsClose(std::string(__FUNCTION__));
    isCleared_.store(true);
    return E_OK;
}

int PreferencesImpl::WriteToDiskFile(std::shared_ptr<PreferencesImpl> pref)
{
    auto keysModified = std::make_shared<std::unordered_set<std::string>>();
    auto writeToDiskMap = std::make_shared<std::unordered_map<std::string, PreferencesValue>>();
    {
        std::unique_lock<decltype(pref->cacheMutex_)> lock(pref->cacheMutex_);
        if (pref->isCleared_.load()) {
            for (auto &it : pref->valuesCache_) {
                pref->modifiedKeys_.emplace(it.first);
            }
            pref->valuesCache_.clear();
            pref->isCleared_.store(false);
        }
        if (!pref->modifiedKeys_.empty()) {
            *keysModified = std::move(pref->modifiedKeys_);
            *writeToDiskMap = pref->valuesCache_;
        } else {
            // Cache has not changed, Not need to write persistent files.
            LOG_INFO("No data to update persistent file");
            return E_OK;
        }
    }
    if (!PreferencesXmlUtils::WriteSettingXml(pref->options_.filePath, pref->options_.bundleName, *writeToDiskMap)) {
        return E_ERROR;
    }
    if (pref->isNeverUnlock_) {
        pref->isNeverUnlock_ = false;
    }
    if (!pref->loadResult_) {
        pref->loadResult_ = true;
    }

    NotifyPreferencesObserver(pref, keysModified, writeToDiskMap);
    return E_OK;
}

void PreferencesImpl::Flush()
{
    IsClose(std::string(__FUNCTION__));
    auto success = queue_->PushNoWait(1);
    if (!success) {
        return;
    }
    std::weak_ptr<SafeBlockQueue<uint64_t>> queue = queue_;
    ExecutorPool::Task task = [queue, self = weak_from_this()] {
        auto realQueue = queue.lock();
        auto realThis = self.lock();
        if (realQueue == nullptr || realThis == nullptr) {
            return;
        }
        uint64_t value = 0;
        if (!realThis->PreLoad()) {
            return;
        }
        std::lock_guard<std::mutex> lock(realThis->mutex_);
        auto has = realQueue->PopNotWait(value);
        if (has && value == 1) {
            PreferencesImpl::WriteToDiskFile(realThis);
        }
    };
    executorPool_.Schedule(std::chrono::milliseconds(TASK_EXEC_TIME), std::move(task));
}

int PreferencesImpl::FlushSync()
{
    IsClose(std::string(__FUNCTION__));
    auto success = queue_->PushNoWait(1);
    if (success) {
        if (queue_ == nullptr) {
            return E_ERROR;
        }
        if (!PreLoad()) {
            return E_OK;
        }
        uint64_t value = 0;
        std::lock_guard<std::mutex> lock(mutex_);
        auto has = queue_->PopNotWait(value);
        if (has && value == 1) {
            return PreferencesImpl::WriteToDiskFile(shared_from_this());
        }
    }
    return E_OK;
}

std::pair<int, PreferencesValue> PreferencesImpl::GetValue(const std::string &key, const PreferencesValue &defValue)
{
    int errCode = CheckKey(key);
    if (errCode != E_OK) {
        return std::make_pair(errCode, defValue);
    }

    AwaitLoadFile();
    IsClose(std::string(__FUNCTION__));
    std::shared_lock<decltype(cacheMutex_)> lock(cacheMutex_);
    if (!isCleared_.load()) {
        auto iter = valuesCache_.find(key);
        if (iter != valuesCache_.end()) {
            return std::make_pair(E_OK, iter->second);
        }
    }
    return std::make_pair(E_NO_DATA, defValue);
}

std::pair<int, std::map<std::string, PreferencesValue>> PreferencesImpl::GetAllData()
{
    AwaitLoadFile();
    IsClose(std::string(__FUNCTION__));
    std::map<std::string, PreferencesValue> allDatas;
    std::shared_lock<decltype(cacheMutex_)> lock(cacheMutex_);
    if (!isCleared_.load()) {
        for (auto &it : valuesCache_) {
            allDatas.insert_or_assign(it.first, it.second);
        }
    }
    return std::make_pair(E_OK, allDatas);
}

std::unordered_map<std::string, PreferencesValue> PreferencesImpl::GetAllDatas()
{
    AwaitLoadFile();
    IsClose(std::string(__FUNCTION__));
    std::shared_lock<decltype(cacheMutex_)> lock(cacheMutex_);
    if (!isCleared_.load()) {
        return valuesCache_;
    }
    return {};
}

void PreferencesImpl::NotifyPreferencesObserver(std::shared_ptr<PreferencesImpl> pref,
    std::shared_ptr<std::unordered_set<std::string>> keysModified,
    std::shared_ptr<std::unordered_map<std::string, PreferencesValue>> writeToDisk)
{
    if (keysModified->empty()) {
        return;
    }
    std::shared_lock<std::shared_mutex> autoLock(pref->obseverMetux_);
    for (const auto &[weakPrt, keys] : pref->dataObserversMap_) {
        std::map<std::string, PreferencesValue> records;
        for (auto &key : *keysModified) {
            auto itKey = keys.find(key);
            if (itKey == keys.end()) {
                continue;
            }
            PreferencesValue value;
            auto dataIt = writeToDisk->find(key);
            if (dataIt != writeToDisk->end()) {
                value = dataIt->second;
            }
            records.insert({key, value});
        }
        if (records.empty()) {
            continue;
        }
        if (std::shared_ptr<PreferencesObserver> sharedPtr = weakPrt.lock()) {
            sharedPtr->OnChange(records);
        }
    }

    for (auto &it : pref->localObservers_) {
        for (auto &key : *keysModified) {
            std::weak_ptr<PreferencesObserver> weakPreferencesObserver = it;
            if (std::shared_ptr<PreferencesObserver> sharedPreferencesObserver = weakPreferencesObserver.lock()) {
                sharedPreferencesObserver->OnChange(key);
            }
        }
    }

    ExecutorPool::Task task = [pref, keysModified] {
        if (pref == nullptr || pref->dataObsMgrClient_ == nullptr) {
            return;
        }
        for (auto &key : *keysModified) {
            LOG_INFO("The %{public}s is changed, the observer needs to be triggered.",
                Anonymous::ToBeAnonymous(key).c_str());
            pref->dataObsMgrClient_->NotifyChange(pref->MakeUri(key));
        }
    };
    executorPool_.Execute(std::move(task));
}
} // End of namespace NativePreferences
} // End of namespace OHOS
