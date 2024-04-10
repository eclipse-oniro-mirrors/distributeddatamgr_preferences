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

#ifndef PREFERENCES_BASE_H
#define PREFERENCES_BASE_H

#include <any>
#include <condition_variable>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "preferences.h"
#include "preferences_observer.h"
#include "preferences_utils.h"

namespace OHOS {
template <typename T> class sptr;
class Uri;
namespace NativePreferences {
class DataPreferencesObserverStub;
/**
 * The function class of the preference. Various operations on preferences instances are provided in this class.
 */
class PreferencesBase : public Preferences {
public:
    PreferencesBase(const Options &options);
    ~PreferencesBase();

    PreferencesValue Get(const std::string &key, const PreferencesValue &defValue) override;

    int Put(const std::string &key, const PreferencesValue &value) override;

    int GetInt(const std::string &key, const int &defValue) override;

    std::string GetString(const std::string &key, const std::string &defValue) override;

    bool GetBool(const std::string &key, const bool &defValue) override;

    float GetFloat(const std::string &key, const float &defValue) override;

    double GetDouble(const std::string &key, const double &defValue) override;

    int64_t GetLong(const std::string &key, const int64_t &defValue) override;

    std::map<std::string, PreferencesValue> GetAll() override;

    bool HasKey(const std::string &key) override;

    int PutInt(const std::string &key, int value) override;

    int PutString(const std::string &key, const std::string &value) override;

    int PutBool(const std::string &key, bool value) override;

    int PutLong(const std::string &key, int64_t value) override;

    int PutFloat(const std::string &key, float value) override;

    int PutDouble(const std::string &key, double value) override;

    int Delete(const std::string &key) override;

    int Clear() override;

    void Flush() override;

    int FlushSync() override;

    int RegisterObserver(std::shared_ptr<PreferencesObserver> preferencesObserver,
        RegisterMode mode = RegisterMode::LOCAL_CHANGE) override;

    int UnRegisterObserver(std::shared_ptr<PreferencesObserver> preferencesObserver,
        RegisterMode mode = RegisterMode::LOCAL_CHANGE) override;

    int RegisterDataObserver(std::shared_ptr<PreferencesObserver> preferencesObserver,
        const std::vector<std::string> &keys = {}) override;

    int UnRegisterDataObserver(std::shared_ptr<PreferencesObserver> preferencesObserver,
        const std::vector<std::string> &keys = {}) override;

    std::string GetGroupId() const override;
protected:
    Uri MakeUri(const std::string &key = "");
    struct WeakPtrCompare {
        bool operator()(const std::weak_ptr<PreferencesObserver> &a, const std::weak_ptr<PreferencesObserver> &b) const
        {
            return a.owner_before(b);
        }
    };
    using DataObserverMap = std::map<std::weak_ptr<PreferencesObserver>, std::set<std::string>, WeakPtrCompare>;
    std::mutex mutex_;
    std::condition_variable cond_;

    std::vector<std::weak_ptr<PreferencesObserver>> localObservers_;
    std::vector<sptr<DataPreferencesObserverStub>> multiProcessObservers_;
    DataObserverMap dataObserversMap_;

    const Options options_;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_H
