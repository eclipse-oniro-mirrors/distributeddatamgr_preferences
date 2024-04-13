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

#include "preferences_base.h"

namespace OHOS {
namespace NativePreferences {
class ExecutorPool;
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
private:
    explicit PreferencesImpl(const Options &options);
    class MemoryToDiskRequest {
    public:
        MemoryToDiskRequest(const std::map<std::string, PreferencesValue> &writeToDiskMap,
            const std::list<std::string> &keysModified,
            const std::vector<std::weak_ptr<PreferencesObserver>> preferencesObservers, int64_t memStataGeneration,
            const DataObserverMap preferencesDataObservers);
        ~MemoryToDiskRequest() {}
        void SetDiskWriteResult(bool wasWritten, int result);

        bool isSyncRequest_;
        int64_t memoryStateGeneration_;
        std::map<std::string, PreferencesValue> writeToDiskMap_;
        std::condition_variable reqCond_;
        std::list<std::string> keysModified_;
        std::vector<std::weak_ptr<PreferencesObserver>> localObservers_;
        DataObserverMap dataObserversMap_;

        int writeToDiskResult_;
        bool wasWritten_;
    };

    std::shared_ptr<MemoryToDiskRequest> commitToMemory();
    void NotifyPreferencesObserver(const MemoryToDiskRequest &request);
    bool StartLoadFromDisk();

    /* thread function */
    static void LoadFromDisk(std::shared_ptr<PreferencesImpl> pref);
    void AwaitLoadFile();
    static void WriteToDiskFile(std::shared_ptr<PreferencesImpl> pref, std::shared_ptr<MemoryToDiskRequest> mcr);
    bool CheckRequestValidForStateGeneration(std::shared_ptr<MemoryToDiskRequest> mcr);
    bool ReadSettingXml(std::shared_ptr<PreferencesImpl> pref);
    bool WriteSettingXml(std::shared_ptr<PreferencesImpl> pref, const std::map<std::string, PreferencesValue> &prefMap);

    bool loaded_;

    /* Current memory state (always increasing) */
    int64_t currentMemoryStateGeneration_;
    /* Latest memory state that was committed to disk */
    int64_t diskStateGeneration_;

    std::list<std::string> modifiedKeys_;

    static ExecutorPool executorPool_;

    std::map<std::string, PreferencesValue> map_;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_IMPL_H
