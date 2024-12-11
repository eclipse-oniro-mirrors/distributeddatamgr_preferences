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
#include <chrono>
#include <cinttypes>

#include "base64_helper.h"
#include "executor_pool.h"
#include "log_print.h"
#include "preferences_observer_stub.h"
#include "preferences_xml_utils.h"
#include "preferences_file_operation.h"
#include "preferences_anonymous.h"

namespace OHOS {
namespace NativePreferences {

using namespace std::chrono;

constexpr int32_t WAIT_TIME = 2;
constexpr int32_t TASK_EXEC_TIME = 100;
constexpr int32_t THREE_SECONDS = 3000;

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

PreferencesImpl::PreferencesImpl(const Options &options) : PreferencesBase(options)
{
    loaded_.store(false);
    fileExist_.store(false);
    currentMemoryStateGeneration_ = 0;
    diskStateGeneration_ = 0;
    queue_ = std::make_shared<SafeBlockQueue<uint64_t>>(1);
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
    loaded_.store(false);
    fileExist_.store(false);

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
    loadBeginTime_ = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    if (!pref->loaded_.load()) {
        if (Access(pref->options_.filePath) == 0) {
            fileExist_.store(true);
        }
        bool loadResult = PreferencesImpl::ReadSettingXml(pref);
        if (!loadResult) {
            LOG_WARN("The settingXml %{public}s load failed.", ExtractFileName(pref->options_.filePath).c_str());
        }
        pref->loaded_.store(true);
        pref->cond_.notify_all();
    }
}

void PreferencesImpl::ReloadFromDisk(std::shared_ptr<PreferencesImpl> pref)
{
    if (pref->fileExist_.load()) {
        return;
    }
    std::lock_guard<std::mutex> lock(pref->mutex_);
    if (!pref->fileExist_.load()) {
        if (Access(pref->options_.filePath) == 0) {
            bool loadResult = PreferencesImpl::RereadSettingXml(pref);
            LOG_WARN("The settingXml %{public}s reload result is %{public}d",
                ExtractFileName(pref->options_.filePath).c_str(), loadResult);
            if (loadResult) {
                fileExist_.store(true);
            }
        }
    }
}

void PreferencesImpl::AwaitLoadFile()
{
    if (loaded_.load()) {
        if (!fileExist_.load() && Access(options_.filePath) == 0) {
            ExecutorPool::Task task = [pref = shared_from_this()] { PreferencesImpl::ReloadFromDisk(pref); };
            executorPool_.Execute(std::move(task));
        }
        return;
    }
    auto nowMs = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    if (nowMs - loadBeginTime_ > THREE_SECONDS) {
        LOG_ERROR("The settingXml %{public}s load time exceed 3s, load begin time:%{public}", PRIu64,
            ExtractFileName(options_.filePath).c_str(), loadBeginTime_);
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

    auto it = valuesCache_.Find(key);
    if (it.first) {
        return it.second;
    }
    return defValue;
}

std::map<std::string, PreferencesValue> PreferencesImpl::GetAll()
{
    AwaitLoadFile();
    return valuesCache_.Clone();
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
    LOG_WARN("unknown element type. the key is %{public}s", Anonymous::ToBeAnonymous(element.key_).c_str());
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

void RereadXmlElement(const Element &element, ConcurrentMap<std::string, PreferencesValue> &prefConMap)
{
    PreferencesValue value(static_cast<int64_t>(0));
    if (Convert2PrefValue(element, value.value_)) {
        prefConMap.Insert(element.key_, value);
    }
}

bool PreferencesImpl::ReadSettingXml(std::shared_ptr<PreferencesImpl> pref)
{
    std::vector<Element> settings;
    if (!PreferencesXmlUtils::ReadSettingXml(pref->options_.filePath, pref->options_.bundleName,
        pref->options_.dataGroupId, settings)) {
        return false;
    }

    std::map<std::string, PreferencesValue> values;
    for (const auto &element : settings) {
        ReadXmlElement(element, values);
    }
    pref->valuesCache_ = std::move(values);
    return true;
}

bool PreferencesImpl::RereadSettingXml(std::shared_ptr<PreferencesImpl> pref)
{
    std::vector<Element> settings;
    if (!PreferencesXmlUtils::ReadSettingXml(pref->options_.filePath, pref->options_.bundleName,
        pref->options_.dataGroupId, settings)) {
        return false;
    }

    for (const auto &element : settings) {
        RereadXmlElement(element, pref->valuesCache_);
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
    LOG_WARN("unknown element type. the key is %{public}s", Anonymous::ToBeAnonymous(elem.key_).c_str());
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
    const Options &options, const std::map<std::string, PreferencesValue> &writeToDiskMap)
{
    std::vector<Element> settings;
    for (auto it = writeToDiskMap.begin(); it != writeToDiskMap.end(); it++) {
        Element elem;
        elem.key_ = it->first;
        PreferencesValue value = it->second;
        WriteXmlElement(elem, value);
        settings.push_back(elem);
    }

    return PreferencesXmlUtils::WriteSettingXml(options.filePath, options.bundleName, options.dataGroupId, settings);
}


bool PreferencesImpl::HasKey(const std::string &key)
{
    if (CheckKey(key) != E_OK) {
        return false;
    }

    AwaitLoadFile();
    return valuesCache_.Contains(key);
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

    valuesCache_.Compute(key, [this, &value](auto &key, PreferencesValue &val) {
        if (val == value) {
            return true;
        }
        val = value;
        modifiedKeys_.push_back(key);
        return true;
    });
    return E_OK;
}

int PreferencesImpl::Delete(const std::string &key)
{
    int errCode = CheckKey(key);
    if (errCode != E_OK) {
        return errCode;
    }
    AwaitLoadFile();
    valuesCache_.EraseIf(key, [this](auto &key, PreferencesValue &val) {
        modifiedKeys_.push_back(key);
        return true;
    });
    return E_OK;
}

int PreferencesImpl::Clear()
{
    AwaitLoadFile();
    valuesCache_.EraseIf([this](auto &key, PreferencesValue &val) {
        modifiedKeys_.push_back(key);
        return true;
    });
    return E_OK;
}

int PreferencesImpl::WriteToDiskFile(std::shared_ptr<PreferencesImpl> pref)
{
    std::list<std::string> keysModified;
    std::map<std::string, PreferencesValue> writeToDiskMap;
    pref->valuesCache_.DoActionWhenClone(
        [pref, &writeToDiskMap, &keysModified](const std::map<std::string, PreferencesValue> &map) {
        if (!pref->modifiedKeys_.empty()) {
            keysModified = std::move(pref->modifiedKeys_);
        }
        writeToDiskMap = std::move(map);
    });

    // Cache has not changed, Not need to write persistent files.
    if (keysModified.empty()) {
        LOG_INFO("No data to update persistent file");
        return E_OK;
    }
    if (!pref->WriteSettingXml(pref->options_, writeToDiskMap)) {
        return E_ERROR;
    }
    if (!pref->fileExist_.load()) {
        pref->fileExist_.store(true);
    }
    pref->NotifyPreferencesObserver(keysModified, writeToDiskMap);
    return E_OK;
}

void PreferencesImpl::Flush()
{
    auto success = queue_->PushNoWait(1);
    if (success) {
        std::weak_ptr<SafeBlockQueue<uint64_t>> queue = queue_;
        ExecutorPool::Task task = [queue, self = weak_from_this()] {
            auto realQueue = queue.lock();
            auto realThis = self.lock();
            if (realQueue == nullptr || realThis == nullptr) {
                return;
            }
            uint64_t value = 0;
            if (realThis->loaded_.load()) {
                if (!fileExist_.load() && Access(realThis->options_.filePath) == 0) {
                    PreferencesImpl::ReloadFromDisk(realThis);
                }
            }
            std::lock_guard<std::mutex> lock(realThis->mutex_);
            auto has = realQueue->PopNotWait(value);
            if (has && value == 1) {
                PreferencesImpl::WriteToDiskFile(realThis);
            }
        };
        executorPool_.Schedule(std::chrono::milliseconds(TASK_EXEC_TIME), std::move(task));
    }
}

int PreferencesImpl::FlushSync()
{
    auto success = queue_->PushNoWait(1);
    if (success) {
        if (queue_ == nullptr) {
            return E_ERROR;
        }
        if (loaded_.load()) {
            if (!fileExist_.load() && Access(options_.filePath) == 0) {
                PreferencesImpl::ReloadFromDisk(realThis);
            }
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
    auto iter = valuesCache_.Find(key);
    if (iter.first) {
        return std::make_pair(E_OK, iter.second);
    }
    return std::make_pair(E_NO_DATA, defValue);
}

std::pair<int, std::map<std::string, PreferencesValue>> PreferencesImpl::GetAllData()
{
    AwaitLoadFile();
    return std::make_pair(E_OK, valuesCache_.Clone());
}

void PreferencesImpl::NotifyPreferencesObserver(const std::list<std::string> &keysModified,
    const std::map<std::string, PreferencesValue> &writeToDiskMap)
{
    if (keysModified.empty()) {
        return;
    }
    LOG_DEBUG("notify observer size:%{public}zu", dataObserversMap_.size());
    std::shared_lock<std::shared_mutex> autoLock(obseverMetux_);
    for (const auto &[weakPrt, keys] : dataObserversMap_) {
        std::map<std::string, PreferencesValue> records;
        for (auto key = keysModified.begin(); key != keysModified.end(); ++key) {
            auto itKey = keys.find(*key);
            if (itKey == keys.end()) {
                continue;
            }
            PreferencesValue value;
            auto dataIt = writeToDiskMap.find(*key);
            if (dataIt != writeToDiskMap.end()) {
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
    for (auto key = keysModified.begin(); key != keysModified.end(); ++key) {
        for (auto it = localObservers_.begin(); it != localObservers_.end(); ++it) {
            std::weak_ptr<PreferencesObserver> weakPreferencesObserver = *it;
            if (std::shared_ptr<PreferencesObserver> sharedPreferencesObserver = weakPreferencesObserver.lock()) {
                sharedPreferencesObserver->OnChange(*key);
            }
        }

        if (dataObsMgrClient == nullptr) {
            continue;
        }
        LOG_INFO("The %{public}s is changed, the observer needs to be triggered.",
            Anonymous::ToBeAnonymous(*key).c_str());
        dataObsMgrClient->NotifyChange(MakeUri(*key));
    }
}
} // End of namespace NativePreferences
} // End of namespace OHOS
