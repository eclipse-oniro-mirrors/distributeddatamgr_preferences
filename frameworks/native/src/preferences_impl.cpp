/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "preferences_impl.h"

#include <cinttypes>
#include <climits>
#include <cstdlib>
#include <functional>
#include <sstream>
#include <thread>

#include "adaptor.h"
#include "data_preferences_observer_stub.h"
#include "executor_pool.h"
#include "log_print.h"
#include "preferences_errno.h"
#include "preferences_xml_utils.h"
#include "securec.h"

namespace OHOS {
namespace NativePreferences {
ExecutorPool PreferencesImpl::executorPool_ = ExecutorPool(1, 0);

PreferencesImpl::PreferencesImpl(const Options &options) : loaded_(false), options_(options)
{
    currentMemoryStateGeneration_ = 0;
    diskStateGeneration_ = 0;
}

std::string PreferencesImpl::MakeFilePath(const std::string &prefPath, const std::string &suffix)
{
    std::string filePath = prefPath;
    filePath += suffix;
    return filePath;
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
    {
        std::lock_guard<std::mutex> lock(mutex_);
        loaded_ = false;
    }

    ExecutorPool::Task task = std::bind(PreferencesImpl::LoadFromDisk, shared_from_this());
    return (executorPool_.Execute(std::move(task)) == ExecutorPool::INVALID_TASK_ID) ? false : true;
}

int PreferencesImpl::CheckKey(const std::string &key)
{
    if (key.empty()) {
        LOG_ERROR("The key string is null or empty.");
        return E_KEY_EMPTY;
    }
    if (Preferences::MAX_KEY_LENGTH < key.length()) {
        LOG_ERROR("The key string length should shorter than 80.");
        return E_KEY_EXCEED_MAX_LENGTH;
    }
    return E_OK;
}

/* static */
void PreferencesImpl::LoadFromDisk(std::shared_ptr<PreferencesImpl> pref)
{
    std::lock_guard<std::mutex> lock(pref->mutex_);
    if (pref->loaded_) {
        return;
    }
    pref->ReadSettingXml(pref->options_.filePath, pref->map_);
    pref->loaded_ = true;
    pref->cond_.notify_all();
}

void PreferencesImpl::AwaitLoadFile()
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (!loaded_) {
        cond_.wait(lock, [this] { return loaded_; });
    }
}

void PreferencesImpl::WriteToDiskFile(std::shared_ptr<PreferencesImpl> pref, std::shared_ptr<MemoryToDiskRequest> mcr)
{
    if (!pref->CheckRequestValidForStateGeneration(mcr)) {
        mcr->SetDiskWriteResult(true, E_OK);
        return;
    }

    if (pref->WriteSettingXml(pref->options_.filePath, mcr->writeToDiskMap_)) {
        pref->diskStateGeneration_ = mcr->memoryStateGeneration_;
        mcr->SetDiskWriteResult(true, E_OK);
    } else {
        mcr->SetDiskWriteResult(false, E_ERROR);
    }
}

bool PreferencesImpl::CheckRequestValidForStateGeneration(std::shared_ptr<MemoryToDiskRequest> mcr)
{
    if (diskStateGeneration_ >= mcr->memoryStateGeneration_) {
        LOG_INFO("DiskStateGeneration should be less than memoryStateGeneration.");
        return false;
    }

    if (mcr->isSyncRequest_ || currentMemoryStateGeneration_ == mcr->memoryStateGeneration_) {
        return true;
    }
    return false;
}

PreferencesValue PreferencesImpl::Get(const std::string &key, const PreferencesValue &defValue)
{
    if (CheckKey(key) != E_OK) {
        return defValue;
    }

    AwaitLoadFile();
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = map_.find(key);
    if (iter != map_.end()) {
        return iter->second;
    }
    return defValue;
}

std::map<std::string, PreferencesValue> PreferencesImpl::GetAll()
{
    AwaitLoadFile();
    return map_;
}

void ReadXmlArrayElement(const Element &element, std::map<std::string, PreferencesValue> &prefMap)
{
    if (element.tag_.compare("doubleArray") == 0) {
        std::vector<double> values;
        for (auto &child : element.children_) {
            std::stringstream ss;
            ss << child.value_;
            double value = 0.0;
            ss >> value;
            values.push_back(value);
        }
        prefMap.insert(std::make_pair(element.key_, PreferencesValue(values)));
    } else if (element.tag_.compare("stringArray") == 0) {
        std::vector<std::string> values;
        for (auto &child : element.children_) {
            values.push_back(child.value_);
        }
        prefMap.insert(std::make_pair(element.key_, PreferencesValue(values)));
    } else if (element.tag_.compare("boolArray") == 0) {
        std::vector<bool> values;
        for (auto &child : element.children_) {
            std::stringstream ss;
            ss << child.value_;
            int32_t value = 0;
            ss >> value;
            values.push_back(value);
        }
        prefMap.insert(std::make_pair(element.key_, PreferencesValue(values)));
    }
}

void ReadXmlElement(
    const Element &element, std::map<std::string, PreferencesValue> &prefMap, const std::string &prefPath)
{
    if (element.tag_.compare("int") == 0) {
        std::stringstream ss;
        ss << element.value_;
        int value = 0;
        ss >> value;
        prefMap.insert(std::make_pair(element.key_, PreferencesValue(value)));
    } else if (element.tag_.compare("bool") == 0) {
        bool value = (element.value_.compare("true") == 0) ? true : false;
        prefMap.insert(std::make_pair(element.key_, PreferencesValue(value)));
    } else if (element.tag_.compare("long") == 0) {
        std::stringstream ss;
        ss << element.value_;
        int64_t value = 0;
        ss >> value;
        prefMap.insert(std::make_pair(element.key_, PreferencesValue(value)));
    } else if (element.tag_.compare("float") == 0) {
        std::stringstream ss;
        ss << element.value_;
        float value = 0.0;
        ss >> value;
        prefMap.insert(std::make_pair(element.key_, PreferencesValue(value)));
    } else if (element.tag_.compare("double") == 0) {
        std::stringstream ss;
        ss << element.value_;
        double value = 0.0;
        ss >> value;
        prefMap.insert(std::make_pair(element.key_, PreferencesValue(value)));
    } else if (element.tag_.compare("string") == 0) {
        prefMap.insert(std::make_pair(element.key_, PreferencesValue(element.value_)));
    } else if (element.tag_.compare("doubleArray") == 0 || element.tag_.compare("stringArray") == 0
               || element.tag_.compare("boolArray") == 0) {
        ReadXmlArrayElement(element, prefMap);
    } else {
        LOG_WARN("ReadSettingXml:%{private}s, unknown element tag:%{public}s.", prefPath.c_str(), element.tag_.c_str());
    }
}

bool PreferencesImpl::ReadSettingXml(const std::string &prefPath, std::map<std::string, PreferencesValue> &prefMap)
{
    std::vector<Element> settings;
    if (!PreferencesXmlUtils::ReadSettingXml(prefPath, settings)) {
        return false;
    }

    for (const auto &element : settings) {
        ReadXmlElement(element, prefMap, prefPath);
    }
    return true;
}

void WriteXmlElement(Element &elem, const PreferencesValue &value, const std::string &filePath)
{
    if (value.IsDoubleArray()) {
        elem.tag_ = std::string("doubleArray");
        auto values = (std::vector<double>)value;
        for (double val : values) {
            Element element;
            element.tag_ = std::string("double");
            element.value_ = std::to_string((double)val);
            elem.children_.push_back(element);
        }
    } else if (value.IsBoolArray()) {
        elem.tag_ = std::string("boolArray");
        auto values = (std::vector<bool>)value;
        for (bool val : values) {
            Element element;
            element.tag_ = std::string("bool");
            std::string tmpVal = std::to_string((bool)val);
            element.value_ = tmpVal == "1" ? "true" : "false";
            elem.children_.push_back(element);
        }
    } else if (value.IsStringArray()) {
        elem.tag_ = std::string("stringArray");
        auto values = (std::vector<std::string>)value;
        for (std::string &val : values) {
            Element element;
            element.tag_ = std::string("string");
            element.value_ = val;
            elem.children_.push_back(element);
        }
    } else if (value.IsInt()) {
        elem.tag_ = std::string("int");
        elem.value_ = std::to_string((int)value);
    } else if (value.IsBool()) {
        elem.tag_ = std::string("bool");
        std::string tmpVal = std::to_string((bool)value);
        elem.value_ = tmpVal == "1" ? "true" : "false";
    } else if (value.IsLong()) {
        elem.tag_ = std::string("long");
        elem.value_ = std::to_string((int64_t)value);
    } else if (value.IsFloat()) {
        elem.tag_ = std::string("float");
        elem.value_ = std::to_string((float)value);
    } else if (value.IsDouble()) {
        elem.tag_ = std::string("double");
        elem.value_ = std::to_string((double)value);
    } else if (value.IsString()) {
        elem.tag_ = std::string("string");
        elem.value_ = std::string(value);
    } else {
        LOG_WARN("WriteSettingXml:%{private}s, unknown element type.", filePath.c_str());
    }
}

bool PreferencesImpl::WriteSettingXml(
    const std::string &prefPath, const std::map<std::string, PreferencesValue> &prefMap)
{
    std::vector<Element> settings;
    for (auto it = prefMap.begin(); it != prefMap.end(); it++) {
        Element elem;
        elem.key_ = it->first;
        PreferencesValue value = it->second;

        WriteXmlElement(elem, value, prefPath);
        settings.push_back(elem);
    }

    return PreferencesXmlUtils::WriteSettingXml(prefPath, settings);
}

bool PreferencesImpl::HasKey(const std::string &key)
{
    if (CheckKey(key) != E_OK) {
        return false;
    }

    AwaitLoadFile();

    std::lock_guard<std::mutex> lock(mutex_);
    return (map_.find(key) != map_.end());
}

int PreferencesImpl::RegisterObserver(std::shared_ptr<PreferencesObserver> preferencesObserver, RegisterMode mode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (mode == RegisterMode::LOCAL_CHANGE) {
        std::weak_ptr<PreferencesObserver> weakPreferencesObserver = preferencesObserver;
        localObservers_.push_back(weakPreferencesObserver);
    } else {
        auto dataObsMgrClient = DataObsMgrClient::GetInstance();
        if (dataObsMgrClient == nullptr) {
            return E_GET_DATAOBSMGRCLIENT_FAIL;
        }
        sptr<DataPreferencesObserverStub> observer(new (std::nothrow) DataPreferencesObserverStub(preferencesObserver));
        int errcode = dataObsMgrClient->RegisterObserver(MakeUri(), observer);
        if (errcode != 0) {
            LOG_ERROR("RegisterObserver multiProcessChange failed, errCode %{public}d", errcode);
            return errcode;
        }
        multiProcessObservers_.push_back(observer);
    }
    return E_OK;
}

int PreferencesImpl::UnRegisterObserver(std::shared_ptr<PreferencesObserver> preferencesObserver, RegisterMode mode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (mode == RegisterMode::LOCAL_CHANGE) {
        for (auto it = localObservers_.begin(); it != localObservers_.end(); ++it) {
            std::weak_ptr<PreferencesObserver> weakPreferencesObserver = *it;
            std::shared_ptr<PreferencesObserver> sharedObserver = weakPreferencesObserver.lock();
            if (!sharedObserver || sharedObserver == preferencesObserver) {
                localObservers_.erase(it);
                break;
            }
        }
        return E_OK;
    }
    for (auto it = multiProcessObservers_.begin(); it != multiProcessObservers_.end(); ++it) {
        std::shared_ptr<PreferencesObserver> sharedObserver = (*it)->preferencesObserver_.lock();
        if (!sharedObserver || sharedObserver == preferencesObserver) {
            auto dataObsMgrClient = DataObsMgrClient::GetInstance();
            if (dataObsMgrClient == nullptr) {
                return E_GET_DATAOBSMGRCLIENT_FAIL;
            }
            int errcode = dataObsMgrClient->UnregisterObserver(MakeUri(), *it);
            if (errcode != 0) {
                LOG_ERROR("RegisterObserver multiProcessChange failed, errCode %{public}d", errcode);
                return errcode;
            }
            multiProcessObservers_.erase(it);
            break;
        }
    }
    return E_OK;
}

int PreferencesImpl::Put(const std::string &key, const PreferencesValue &value)
{
    int errCode = CheckKey(key);
    if (errCode != E_OK) {
        return errCode;
    }
    if (value.IsString()) {
        errCode = CheckStringValue(value);
        if (errCode != E_OK) {
            LOG_ERROR("PreferencesImpl::Put string value length should shorter than 8*1024");
            return errCode;
        }
    }

    AwaitLoadFile();

    std::lock_guard<std::mutex> lock(mutex_);

    auto iter = map_.find(key);
    if (iter != map_.end()) {
        PreferencesValue &val = iter->second;
        if (val == value) {
            return E_OK;
        }
    }

    map_.insert_or_assign(key, value);
    modifiedKeys_.push_back(key);
    return E_OK;
}

int PreferencesImpl::CheckStringValue(const std::string &value)
{
    if (Preferences::MAX_VALUE_LENGTH < value.length()) {
        LOG_ERROR("The value string length should shorter than 8 * 1024.");
        return E_VALUE_EXCEED_MAX_LENGTH;
    }
    return E_OK;
}

Uri PreferencesImpl::MakeUri(const std::string &key)
{
    std::string uriStr;
    if (options_.dataGroupId.empty()) {
        uriStr = STR_SCHEME + options_.bundleName + STR_SLASH + options_.filePath;
    } else {
        uriStr = STR_SCHEME + options_.dataGroupId + STR_SLASH + options_.filePath;
    }

    if (!key.empty()) {
        uriStr = uriStr + STR_QUERY + key;
    }
    return Uri(uriStr);
}

int PreferencesImpl::Delete(const std::string &key)
{
    int errCode = CheckKey(key);
    if (errCode != E_OK) {
        return errCode;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto pos = map_.find(key);
    if (pos != map_.end()) {
        map_.erase(pos);
        modifiedKeys_.push_back(key);
    }

    return E_OK;
}

int PreferencesImpl::Clear()
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (!map_.empty()) {
        for (auto &kv : map_) {
            modifiedKeys_.push_back(kv.first);
        }
        map_.clear();
    }
    return E_OK;
}

void PreferencesImpl::Flush()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::shared_ptr<PreferencesImpl::MemoryToDiskRequest> request = commitToMemory();
    request->isSyncRequest_ = false;
    ExecutorPool::Task task = std::bind(PreferencesImpl::WriteToDiskFile, shared_from_this(), request);
    executorPool_.Execute(std::move(task));

    notifyPreferencesObserver(*request);
}

int PreferencesImpl::FlushSync()
{
    std::shared_ptr<PreferencesImpl::MemoryToDiskRequest> request = commitToMemory();
    request->isSyncRequest_ = true;
    std::unique_lock<std::mutex> lock(request->reqMutex_);
    PreferencesImpl::WriteToDiskFile(shared_from_this(), request);
    if (request->wasWritten_) {
        LOG_DEBUG("%{private}s:%{public}" PRId64 " written", options_.filePath.c_str(),
            request->memoryStateGeneration_);
    }
    notifyPreferencesObserver(*request);
    return request->writeToDiskResult_;
}

std::shared_ptr<PreferencesImpl::MemoryToDiskRequest> PreferencesImpl::commitToMemory()
{
    std::lock_guard<std::mutex> lock(mutex_);
    int64_t memoryStateGeneration = -1;
    std::list<std::string> keysModified;
    std::vector<std::weak_ptr<PreferencesObserver>> preferencesObservers;
    std::map<std::string, PreferencesValue> writeToDiskMap;
    writeToDiskMap = map_;
    if (!modifiedKeys_.empty()) {
        currentMemoryStateGeneration_++;
        keysModified = modifiedKeys_;
        modifiedKeys_.clear();
    }
    memoryStateGeneration = currentMemoryStateGeneration_;
    preferencesObservers = localObservers_;
    return std::make_shared<MemoryToDiskRequest>(
        writeToDiskMap, keysModified, preferencesObservers, memoryStateGeneration);
}

void PreferencesImpl::notifyPreferencesObserver(const PreferencesImpl::MemoryToDiskRequest &request)
{
    if (request.keysModified_.empty()) {
        return;
    }

    auto dataObsMgrClient = DataObsMgrClient::GetInstance();
    for (auto key = request.keysModified_.begin(); key != request.keysModified_.end(); ++key) {
        for (auto it = request.localObservers_.begin(); it != request.localObservers_.end(); ++it) {
            std::weak_ptr<PreferencesObserver> weakPreferencesObserver = *it;
            if (std::shared_ptr<PreferencesObserver> sharedPreferencesObserver = weakPreferencesObserver.lock()) {
                sharedPreferencesObserver->OnChange(*key);
            }
        }
        
        if (dataObsMgrClient == nullptr) {
            continue;
        }
        dataObsMgrClient->NotifyChange(MakeUri(*key));
    }
}

PreferencesImpl::MemoryToDiskRequest::MemoryToDiskRequest(
    const std::map<std::string, PreferencesValue> &writeToDiskMap, const std::list<std::string> &keysModified,
    const std::vector<std::weak_ptr<PreferencesObserver>> preferencesObservers, int64_t memStataGeneration)
{
    writeToDiskMap_ = writeToDiskMap;
    keysModified_ = keysModified;
    localObservers_ = preferencesObservers;
    memoryStateGeneration_ = memStataGeneration;
    isSyncRequest_ = false;
    wasWritten_ = false;
    writeToDiskResult_ = E_ERROR;
}

void PreferencesImpl::MemoryToDiskRequest::SetDiskWriteResult(bool wasWritten, int result)
{
    writeToDiskResult_ = result;
    wasWritten_ = wasWritten;
    reqCond_.notify_one();
}
} // End of namespace NativePreferences
} // End of namespace OHOS
