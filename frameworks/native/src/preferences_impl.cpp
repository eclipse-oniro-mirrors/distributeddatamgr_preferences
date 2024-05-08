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
#include <sstream>
#include <thread>

#include "base64_helper.h"
#include "executor_pool.h"
#include "log_print.h"
#include "preferences_observer_stub.h"
#include "preferences_xml_utils.h"
#include "securec.h"

namespace OHOS {
namespace NativePreferences {

constexpr int32_t WAIT_TIME = 2;

template<typename T>
std::string GetTypeName()
{
    return "unknown";
}

template<>
std::string GetTypeName<int>()
{
    return "int";
}

template<>
std::string GetTypeName<bool>()
{
    return "bool";
}

template<>
std::string GetTypeName<int64_t>()
{
    return "long";
}

template<>
std::string GetTypeName<uint64_t>()
{
    return "uint64_t";
}

template<>
std::string GetTypeName<float>()
{
    return "float";
}

template<>
std::string GetTypeName<double>()
{
    return "double";
}

template<>
std::string GetTypeName<std::string>()
{
    return "string";
}

template<>
std::string GetTypeName<std::vector<std::string>>()
{
    return "stringArray";
}

template<>
std::string GetTypeName<std::vector<double>>()
{
    return "doubleArray";
}

template<>
std::string GetTypeName<std::vector<bool>>()
{
    return "boolArray";
}

template<>
std::string GetTypeName<std::vector<uint8_t>>()
{
    return "uint8Array";
}

template<>
std::string GetTypeName<Object>()
{
    return "object";
}

template<>
std::string GetTypeName<BigInt>()
{
    return "BigInt";
}

ExecutorPool PreferencesImpl::executorPool_ = ExecutorPool(1, 0);

PreferencesImpl::PreferencesImpl(const Options &options) : PreferencesBase(options), loaded_(false)
{
    currentMemoryStateGeneration_ = 0;
    diskStateGeneration_ = 0;
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

/* static */
void PreferencesImpl::LoadFromDisk(std::shared_ptr<PreferencesImpl> pref)
{
    std::lock_guard<std::mutex> lock(pref->mutex_);
    if (pref->loaded_) {
        return;
    }
    bool loadResult = pref->ReadSettingXml(pref);
    if (!loadResult) {
        LOG_ERROR("The settingXml load failed.");
    }
    pref->loaded_ = true;
    pref->cond_.notify_all();
}

void PreferencesImpl::AwaitLoadFile()
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (!loaded_) {
        cond_.wait_for(lock, std::chrono::seconds(WAIT_TIME), [this] { return loaded_; });
    }

    if (!loaded_) {
        LOG_ERROR("The settingXml load timeout.");
    }
}

void PreferencesImpl::WriteToDiskFile(std::shared_ptr<PreferencesImpl> pref, std::shared_ptr<MemoryToDiskRequest> mcr)
{
    std::unique_lock<std::mutex> lock(pref->mutex_);
    if (!pref->CheckRequestValidForStateGeneration(mcr)) {
        mcr->SetDiskWriteResult(true, E_OK);
        return;
    }

    if (pref->WriteSettingXml(pref, mcr->writeToDiskMap_)) {
        pref->diskStateGeneration_ = mcr->memoryStateGeneration_;
        mcr->SetDiskWriteResult(true, E_OK);
    } else {
        mcr->SetDiskWriteResult(false, E_ERROR);
    }
}

bool PreferencesImpl::CheckRequestValidForStateGeneration(std::shared_ptr<MemoryToDiskRequest> mcr)
{
    if (diskStateGeneration_ >= mcr->memoryStateGeneration_) {
        LOG_DEBUG("DiskStateGeneration should be less than memoryStateGeneration.");
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
    std::lock_guard<std::mutex> lock(mutex_);
    return map_;
}

template<typename T>
static void Convert2PrefValue(const Element &element, T &value)
{
    if constexpr (std::is_same<T, bool>::value) {
        value = (element.value_.compare("true") == 0) ? true : false;
    } else if constexpr (std::is_same<T, std::string>::value) {
        value = element.value_;
    } else if constexpr (std::is_same<T, std::monostate>::value) {
        value = std::monostate();
    } else {
        std::stringstream ss;
        ss << element.value_;
        ss >> value;
    }
}

template<typename T>
static void Convert2PrefValue(const Element &element, std::vector<T> &values)
{
    for (const auto &child : element.children_) {
        T value;
        Convert2PrefValue(child, value);
        values.push_back(value);
    }
}

static void Convert2PrefValue(const Element &element, BigInt &value)
{
    for (const auto &child : element.children_) {
        uint64_t val;
        Convert2PrefValue(child, val);
        value.words_.push_back(val);
    }
    value.sign_ = 0;
    if (!value.words_.empty()) {
        value.sign_ = static_cast<int>(value.words_[value.words_.size() - 1]);
        value.words_.pop_back();
    }
}

template<typename T>
bool GetPrefValue(const Element &element, T &value)
{
    LOG_WARN("unknown element type. the key is %{public}s", element.key_.c_str());
    return false;
}

static void Convert2PrefValue(const Element &element, std::vector<uint8_t> &value)
{
    if (!Base64Helper::Decode(element.value_, value)) {
        value.clear();
    }
}

static void Convert2PrefValue(const Element &element, Object &value)
{
    value.valueStr = element.value_;
}

template<typename T, typename First, typename... Types>
bool GetPrefValue(const Element &element, T &value)
{
    if (element.tag_ == GetTypeName<First>()) {
        First val;
        Convert2PrefValue(element, val);
        value = val;
        return true;
    }
    return GetPrefValue<T, Types...>(element, value);
}

template<typename... Types>
bool Convert2PrefValue(const Element &element, std::variant<Types...> &value)
{
    return GetPrefValue<decltype(value), Types...>(element, value);
}

void ReadXmlElement(const Element &element, std::map<std::string, PreferencesValue> &prefMap)
{
    PreferencesValue value(static_cast<int64_t>(0));
    if (Convert2PrefValue(element, value.value_)) {
        prefMap.insert(std::make_pair(element.key_, value));
    }
}

bool PreferencesImpl::ReadSettingXml(std::shared_ptr<PreferencesImpl> pref)
{
    std::vector<Element> settings;
    if (!PreferencesXmlUtils::ReadSettingXml(pref->options_.filePath, pref->options_.dataGroupId, settings)) {
        return false;
    }

    for (const auto &element : settings) {
        ReadXmlElement(element, pref->map_);
    }
    return true;
}

template<typename T>
void Convert2Element(Element &elem, const T &value)
{
    elem.tag_ = GetTypeName<T>();
    if constexpr (std::is_same<T, bool>::value) {
        elem.value_ = ((bool)value) ? "true" : "false";
    } else if constexpr (std::is_same<T, std::string>::value) {
        elem.value_ = value;
    } else if constexpr (std::is_same<T, std::monostate>::value) {
        elem.value_ = {};
    } else {
        elem.value_ = std::to_string(value);
    }
}

template<typename T>
void Convert2Element(Element &elem, const std::vector<T> &value)
{
    elem.tag_ = GetTypeName<std::vector<T>>();
    for (const T &val : value) {
        Element element;
        Convert2Element(element, val);
        elem.children_.push_back(element);
    }
}

void Convert2Element(Element &elem, const std::vector<uint8_t> &value)
{
    elem.tag_ = GetTypeName<std::vector<uint8_t>>();
    elem.value_ = Base64Helper::Encode(value);
}

void Convert2Element(Element &elem, const Object &value)
{
    elem.tag_ = GetTypeName<Object>();
    elem.value_ = value.valueStr;
}

void Convert2Element(Element &elem, const BigInt &value)
{
    elem.tag_ = GetTypeName<BigInt>();
    for (const auto &val : value.words_) {
        Element element;
        Convert2Element(element, val);
        elem.children_.push_back(element);
    }
    // place symbol at the end
    Element symbolElement;
    Convert2Element(symbolElement, static_cast<uint64_t>(value.sign_));
    elem.children_.push_back(symbolElement);
}

template<typename T> void GetElement(Element &elem, const T &value)
{
    LOG_WARN("unknown element type. the key is %{public}s", elem.key_.c_str());
}

template<typename T, typename First, typename... Types> void GetElement(Element &elem, const T &value)
{
    auto *val = std::get_if<First>(&value);
    if (val != nullptr) {
        return Convert2Element(elem, *val);
    }
    return GetElement<T, Types...>(elem, value);
}

template<typename... Types> void Convert2Element(Element &elem, const std::variant<Types...> &value)
{
    return GetElement<decltype(value), Types...>(elem, value);
}

void WriteXmlElement(Element &elem, const PreferencesValue &value)
{
    Convert2Element(elem, value.value_);
}

bool PreferencesImpl::WriteSettingXml(
    std::shared_ptr<PreferencesImpl> pref, const std::map<std::string, PreferencesValue> &prefMap)
{
    std::vector<Element> settings;
    for (auto it = prefMap.begin(); it != prefMap.end(); it++) {
        Element elem;
        elem.key_ = it->first;
        PreferencesValue value = it->second;
        WriteXmlElement(elem, value);
        settings.push_back(elem);
    }

    return PreferencesXmlUtils::WriteSettingXml(pref->options_.filePath, pref->options_.dataGroupId, settings);
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
    std::shared_ptr<PreferencesImpl::MemoryToDiskRequest> request = commitToMemory();
    request->isSyncRequest_ = false;
    ExecutorPool::Task task = std::bind(PreferencesImpl::WriteToDiskFile, shared_from_this(), request);
    executorPool_.Execute(std::move(task));

    NotifyPreferencesObserver(*request);
}

int PreferencesImpl::FlushSync()
{
    std::shared_ptr<PreferencesImpl::MemoryToDiskRequest> request = commitToMemory();
    request->isSyncRequest_ = true;
    PreferencesImpl::WriteToDiskFile(shared_from_this(), request);
    if (request->wasWritten_) {
        LOG_DEBUG("Successfully written to disk file, memory state generation is %{public}" PRId64 "",
            request->memoryStateGeneration_);
    }
    NotifyPreferencesObserver(*request);
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
        writeToDiskMap, keysModified, preferencesObservers, memoryStateGeneration, dataObserversMap_);
}

void PreferencesImpl::NotifyPreferencesObserver(const PreferencesImpl::MemoryToDiskRequest &request)
{
    if (request.keysModified_.empty()) {
        return;
    }
    LOG_DEBUG("notify observer size:%{public}zu", request.dataObserversMap_.size());
    for (const auto &[weakPrt, keys] : request.dataObserversMap_) {
        std::map<std::string, PreferencesValue> records;
        for (auto key = request.keysModified_.begin(); key != request.keysModified_.end(); ++key) {
            auto itKey = keys.find(*key);
            if (itKey == keys.end()) {
                continue;
            }
            PreferencesValue value;
            auto dataIt = request.writeToDiskMap_.find(*key);
            if (dataIt != request.writeToDiskMap_.end()) {
                value = dataIt->second;
            }
            records.insert({*key, value});
        }
        if (records.empty()) {
            continue;
        }
        if (std::shared_ptr<PreferencesObserver> sharedPtr = weakPrt.lock()) {
            LOG_DEBUG("dataChange observer call, resultSize:%{public}zu", records.size());
            sharedPtr->OnChange(records);
        }
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
    const std::vector<std::weak_ptr<PreferencesObserver>> preferencesObservers, int64_t memStataGeneration,
    const DataObserverMap preferencesDataObservers)
{
    writeToDiskMap_ = writeToDiskMap;
    keysModified_ = keysModified;
    localObservers_ = preferencesObservers;
    memoryStateGeneration_ = memStataGeneration;
    isSyncRequest_ = false;
    wasWritten_ = false;
    writeToDiskResult_ = E_ERROR;
    dataObserversMap_ = preferencesDataObservers;
}

void PreferencesImpl::MemoryToDiskRequest::SetDiskWriteResult(bool wasWritten, int result)
{
    writeToDiskResult_ = result;
    wasWritten_ = wasWritten;
    reqCond_.notify_one();
}
} // End of namespace NativePreferences
} // End of namespace OHOS
