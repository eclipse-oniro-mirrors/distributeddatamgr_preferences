/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "data_preferences_observer_stub.h"

#include "preferences_errno.h"

namespace OHOS {
namespace NativePreferences {
std::shared_ptr<DataObsMgrClient> DataObsMgrClient::instance_ = nullptr;
std::mutex DataObsMgrClient::mutex_;

DataPreferencesObserverStub::DataPreferencesObserverStub(const std::shared_ptr<PreferencesObserver> preferencesObserver)
    : preferencesObserver_(preferencesObserver)
{
}

DataPreferencesObserverStub::~DataPreferencesObserverStub()
{
}

void DataPreferencesObserverStub::OnChange()
{
}

void DataPreferencesObserverStub::OnChangePreferences(const std::string &key)
{
    std::shared_ptr<PreferencesObserver> sharedPreferencesObserver = preferencesObserver_.lock();
    if (sharedPreferencesObserver != nullptr) {
        sharedPreferencesObserver->OnChange(key);
    }
}

DataObsMgrClient::DataObsMgrClient()
{
}

DataObsMgrClient::~DataObsMgrClient()
{
}

std::shared_ptr<DataObsMgrClient> DataObsMgrClient::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<DataObsMgrClient>();
        }
    }
    return instance_;
}

int DataObsMgrClient::RegisterObserver(const Uri &uri, sptr<DataPreferencesObserverStub> dataObserver)
{
    return E_NOT_SUPPORTED;
}

int DataObsMgrClient::UnregisterObserver(const Uri &uri, sptr<DataPreferencesObserverStub> dataObserver)
{
    return E_NOT_SUPPORTED;
}

int DataObsMgrClient::NotifyChange(const Uri &uri)
{
    return E_NOT_SUPPORTED;
}
} // End of namespace NativePreferences
} // End of namespace OHOS