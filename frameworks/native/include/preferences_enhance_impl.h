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

#ifndef PREFERENCES_ENHANCE_IMPL_H
#define PREFERENCES_ENHANCE_IMPL_H

#include <any>
#include <condition_variable>
#include <filesystem>
#include <list>
#include <map>
#include <string>
#include <vector>
#include <shared_mutex>

#include "preferences_base.h"
#include "preferences_db_adapter.h"

namespace OHOS {
namespace NativePreferences {
class PreferencesEnhanceImpl : public PreferencesBase, public std::enable_shared_from_this<PreferencesEnhanceImpl> {
public:
    static std::shared_ptr<PreferencesEnhanceImpl> GetPreferences(const Options &options)
    {
        return std::shared_ptr<PreferencesEnhanceImpl>(new PreferencesEnhanceImpl(options));
    }
    virtual ~PreferencesEnhanceImpl();

    int Init();

    PreferencesValue Get(const std::string &key, const PreferencesValue &defValue) override;

    int Put(const std::string &key, const PreferencesValue &value) override;

    bool HasKey(const std::string &key) override;

    std::map<std::string, PreferencesValue> GetAll() override;

    int Delete(const std::string &key) override;

    int Clear() override;

    int CloseDb() override;

    std::pair<int, PreferencesValue> GetValue(const std::string &key, const PreferencesValue &defValue) override;

    std::pair<int, std::map<std::string, PreferencesValue>> GetAllData() override;

    std::unordered_map<std::string, PreferencesValue> GetAllDatas() override;
private:
    explicit PreferencesEnhanceImpl(const Options &options);
    static void NotifyPreferencesObserver(std::shared_ptr<PreferencesEnhanceImpl> pref, const std::string &key,
        const PreferencesValue &value);
    static void NotifyPreferencesObserverBatchKeys(std::shared_ptr<PreferencesEnhanceImpl> pref,
        const std::unordered_map<std::string, PreferencesValue> &data);
    std::pair<int, std::unordered_map<std::string, PreferencesValue>> GetAllInner();

    std::shared_mutex dbMutex_;
    std::shared_ptr<PreferencesDb> db_;
    std::shared_mutex mapSharedMutex_;
    int64_t cachedDataVersion_ = 0;
    std::map<std::string, PreferencesValue> largeCachedData_;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_IMPL_H
