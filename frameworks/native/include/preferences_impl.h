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

#ifndef PREFERENCES_IMPL_H
#define PREFERENCES_IMPL_H

#include <any>
#include <condition_variable>
#include <filesystem>
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>
#include <shared_mutex>
#include "safe_block_queue.h"
#include "preferences_base.h"
#include "preferences_observer_stub.h"

namespace OHOS {
namespace NativePreferences {

class PreferencesImpl : public PreferencesBase, public std::enable_shared_from_this<PreferencesImpl> {
public:
    static std::shared_ptr<PreferencesImpl> GetPreferences(const Options &options)
    {
        return std::shared_ptr<PreferencesImpl>(new PreferencesImpl(options));
    }
    virtual ~PreferencesImpl();

    int Init();

    PreferencesValue Get(const std::string &key, const PreferencesValue &defValue) override;

    int Put(const std::string &key, const PreferencesValue &value) override;

    bool HasKey(const std::string &key) override;

    std::map<std::string, PreferencesValue> GetAll() override;

    int Delete(const std::string &key) override;

    int Clear() override;

    void Flush() override;

    int FlushSync() override;

    int Close() override;

    bool IsClose(const std::string &name) override;

    std::pair<int, PreferencesValue> GetValue(const std::string &key, const PreferencesValue &defValue) override;

    std::pair<int, std::map<std::string, PreferencesValue>> GetAllData() override;

    std::unordered_map<std::string, PreferencesValue> GetAllDatas() override;
private:
    explicit PreferencesImpl(const Options &options);

    static void NotifyPreferencesObserver(std::shared_ptr<PreferencesImpl> pref,
        std::shared_ptr<std::unordered_set<std::string>> keysModified,
        std::shared_ptr<std::unordered_map<std::string, PreferencesValue>> writeToDisk);
    bool StartLoadFromDisk();
    bool PreLoad();

    /* thread function */
    static void LoadFromDisk(std::shared_ptr<PreferencesImpl> pref);
    bool ReloadFromDisk();
    inline void AwaitLoadFile();
    static int WriteToDiskFile(std::shared_ptr<PreferencesImpl> pref);
    bool ReadSettingXml(std::unordered_map<std::string, PreferencesValue> &conMap);

    std::atomic<bool> loaded_;
    bool isNeverUnlock_;
    bool loadResult_;

    std::unordered_set<std::string> modifiedKeys_;

    std::atomic<bool> isCleared_;

    std::atomic<bool> isActive_;

    std::shared_mutex cacheMutex_;

    std::unordered_map<std::string, PreferencesValue> valuesCache_;

    std::shared_ptr<SafeBlockQueue<uint64_t>> queue_;

    std::shared_ptr<DataObsMgrClient> dataObsMgrClient_;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_IMPL_H