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
#include <map>
#include <string>
#include <vector>
#include <shared_mutex>
#include "safe_block_queue.h"
#include "concurrent_map.h"
#include "preferences_base.h"

namespace OHOS {
namespace NativePreferences {

enum class ReportedFaultOffset {
    RESTORED_FROM_BAK_OFFSET,
    SCREEN_LOCKED_FAULT_OFFSET
};

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

    std::pair<int, PreferencesValue> GetValue(const std::string &key, const PreferencesValue &defValue) override;

    std::pair<int, std::map<std::string, PreferencesValue>> GetAllData() override;
private:
    explicit PreferencesImpl(const Options &options);

    void NotifyPreferencesObserver(const std::list<std::string> &keysModified,
        const std::map<std::string, PreferencesValue> &writeToDiskMap);
    bool StartLoadFromDisk();
    bool PreLoad();

    /* thread function */
    static void LoadFromDisk(std::shared_ptr<PreferencesImpl> pref);
    bool ReloadFromDisk();
    void AwaitLoadFile();
    void CheckValueUtf8(const std::string &key, const PreferencesValue &value);
    bool WriteSettingXml(const Options &options, const std::map<std::string, PreferencesValue> &writeToDiskMap);
    static int WriteToDiskFile(std::shared_ptr<PreferencesImpl> pref);
    bool ReadSettingXml(ConcurrentMap<std::string, PreferencesValue> &conMap);

    std::atomic<bool> loaded_;
    bool isNeverUnlock_;
    bool loadResult_;

    std::list<std::string> modifiedKeys_;

    ConcurrentMap<std::string, PreferencesValue> valuesCache_;

    std::shared_ptr<SafeBlockQueue<uint64_t>> queue_;
public:
    static ConcurrentMap<std::string, uint64_t> reportedFaults_;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_IMPL_H