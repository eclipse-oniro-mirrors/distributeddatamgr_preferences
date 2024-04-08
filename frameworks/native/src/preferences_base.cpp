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

#include "preferences_base.h"

#include <cinttypes>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <sstream>

#include "base64_helper.h"
#include "log_print.h"
#include "preferences_observer_stub.h"
#include "securec.h"

namespace OHOS {
namespace NativePreferences {
PreferencesBase::PreferencesBase(const Options &options) : options_(options)
{
}

PreferencesBase::~PreferencesBase()
{
}

PreferencesValue PreferencesBase::Get(const std::string &key, const PreferencesValue &defValue)
{
    return defValue;
}

int PreferencesBase::Put(const std::string &key, const PreferencesValue &value)
{
    return E_OK;
}

int PreferencesBase::GetInt(const std::string &key, const int &defValue = {})
{
    PreferencesValue preferencesValue = Get(key, defValue);
    if (!preferencesValue.IsInt()) {
        return defValue;
    }
    return preferencesValue;
}

std::string PreferencesBase::GetString(const std::string &key, const std::string &defValue = {})
{
    PreferencesValue preferencesValue = Get(key, defValue);
    if (!preferencesValue.IsString()) {
        return defValue;
    }
    return preferencesValue;
}
bool PreferencesBase::GetBool(const std::string &key, const bool &defValue = {})
{
    PreferencesValue preferencesValue = Get(key, defValue);
    if (!preferencesValue.IsBool()) {
        return defValue;
    }
    return preferencesValue;
}
float PreferencesBase::GetFloat(const std::string &key, const float &defValue = {})
{
    PreferencesValue preferencesValue = Get(key, defValue);
    if (!preferencesValue.IsFloat()) {
        return defValue;
    }
    return preferencesValue;
}

double PreferencesBase::GetDouble(const std::string &key, const double &defValue = {})
{
    PreferencesValue preferencesValue = Get(key, defValue);
    if (!preferencesValue.IsDouble()) {
        return defValue;
    }
    return preferencesValue;
}

int64_t PreferencesBase::GetLong(const std::string &key, const int64_t &defValue = {})
{
    PreferencesValue preferencesValue = Get(key, defValue);
    if (!preferencesValue.IsLong()) {
        return defValue;
    }
    return preferencesValue;
}

std::map<std::string, PreferencesValue> PreferencesBase::GetAll()
{
    return {};
}

bool PreferencesBase::HasKey(const std::string &key)
{
    return true;
}

int PreferencesBase::PutInt(const std::string &key, int value)
{
    return Put(key, value);
}

int PreferencesBase::PutString(const std::string &key, const std::string &value)
{
    return Put(key, value);
}

int PreferencesBase::PutBool(const std::string &key, bool value)
{
    return Put(key, value);
}

int PreferencesBase::PutLong(const std::string &key, int64_t value)
{
    return Put(key, value);
}

int PreferencesBase::PutFloat(const std::string &key, float value)
{
    return Put(key, value);
}
int PreferencesBase::PutDouble(const std::string &key, double value)
{
    return Put(key, value);
}
int PreferencesBase::Delete(const std::string &key)
{
    return E_OK;
}

int PreferencesBase::Clear()
{
    return E_OK;
}

void PreferencesBase::Flush()
{
}

int PreferencesBase::FlushSync()
{
    return E_OK;
}

int PreferencesBase::RegisterObserver(std::shared_ptr<PreferencesObserver> preferencesObserver, RegisterMode mode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (mode == RegisterMode::LOCAL_CHANGE) {
        std::weak_ptr<PreferencesObserver> weakPreferencesObserver = preferencesObserver;
        localObservers_.push_back(weakPreferencesObserver);
    } else if (mode == RegisterMode::MULTI_PRECESS_CHANGE) {
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

int PreferencesBase::UnRegisterDataObserver(std::shared_ptr<PreferencesObserver> preferencesObserver,
    const std::vector<std::string> &keys)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = dataObserversMap_.find(preferencesObserver);
    if (it == dataObserversMap_.end()) {
        return E_OK;
    }
    for (const auto &key : keys) {
        auto keyIt = it->second.find(key);
        if (keyIt != it->second.end()) {
            it->second.erase(key);
        }
    }
    LOG_DEBUG("UnRegisterObserver keysSize:%{public}zu, curSize:%{public}zu", keys.size(), it->second.size());
    if (keys.empty()) {
        it->second.clear();
    }
    if (it->second.empty()) {
        it = dataObserversMap_.erase(it);
        LOG_DEBUG("UnRegisterObserver finish. obSize:%{public}zu", dataObserversMap_.size());
        return E_OK;
    }
    LOG_DEBUG("UnRegisterObserver finish, observer need reserve. obSize:%{public}zu", dataObserversMap_.size());
    return E_OBSERVER_RESERVE;
}

std::string PreferencesBase::GetGroupId() const
{
    return options_.dataGroupId;
}

int PreferencesBase::RegisterDataObserver(std::shared_ptr<PreferencesObserver> preferencesObserver,
    const std::vector<std::string> &keys)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = dataObserversMap_.find(preferencesObserver);
    if (it == dataObserversMap_.end()) {
        std::set<std::string> callKeys(keys.begin(), keys.end());
        std::weak_ptr<PreferencesObserver> weakPreferencesObserver = preferencesObserver;
        dataObserversMap_.insert({weakPreferencesObserver, std::move(callKeys)});
    } else {
        it->second.insert(keys.begin(), keys.end());
    }
    return E_OK;
}

int PreferencesBase::UnRegisterObserver(std::shared_ptr<PreferencesObserver> preferencesObserver, RegisterMode mode)
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
                LOG_ERROR("UnRegisterObserver multiProcessChange failed, errCode %{public}d", errcode);
                return errcode;
            }
            multiProcessObservers_.erase(it);
            break;
        }
    }
    return E_OK;
}

Uri PreferencesBase::MakeUri(const std::string &key)
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
} // End of namespace NativePreferences
} // End of namespace OHOS
