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

#ifndef PREFERENCES_STORE_IMPL_H
#define PREFERENCES_STORE_IMPL_H

#include <cstdint>
#include <shared_mutex>
#include "oh_preferences.h"
#include "preferences_observer.h"
#include "preferences.h"
#include "log_print.h"

enum PreferencesNdkStructId : std::int64_t {
    PREFERENCES_OH_OPTION_CID = 1002931,
    PREFERENCES_OH_PREFERENCES_CID,
    PREFERENCES_OH_VALUE_CID,
    PREFERENCES_OH_PAIR_CID
};

class NDKPreferencesObserver : public OHOS::NativePreferences::PreferencesObserver {
public:
    NDKPreferencesObserver(OH_PreferencesDataObserver observer, void *context);
    ~NDKPreferencesObserver() noexcept override = default;

    void OnChange(const std::string &key) override;
    void OnChange(const std::map<std::string, OHOS::NativePreferences::PreferencesValue> &records) override;

    bool ObserverCompare(OH_PreferencesDataObserver other);

    OH_PreferencesDataObserver dataObserver_;
    void *context_;
};

struct OH_Preferences {
    int64_t cid;
};

class OH_PreferencesImpl : public OH_Preferences {
public:
    explicit OH_PreferencesImpl(std::shared_ptr<OHOS::NativePreferences::Preferences> preferences);
    ~OH_PreferencesImpl()
    {
        preferences_ = nullptr;
    }
    std::shared_ptr<OHOS::NativePreferences::Preferences> GetNativePreferences()
    {
        return preferences_;
    }

    int RegisterDataObserver(
        OH_PreferencesDataObserver observer, void *context, const std::vector<std::string> &keys = {});
    int UnregisterDataObserver(OH_PreferencesDataObserver observer, void *context,
        const std::vector<std::string> &keys = {});

    void SetPreferencesStoreFilePath(const std::string &filePath);
    std::string GetPreferencesStoreFilePath();

private:
    std::shared_ptr<OHOS::NativePreferences::Preferences> preferences_;
    std::shared_mutex mutex_;
    std::string filePath_ = "";
    std::shared_mutex obsMutex_;
    std::vector<std::pair<std::shared_ptr<NDKPreferencesObserver>, void *>> dataObservers_;
};

struct OH_PreferencesOption {
    int64_t cid;
    std::string fileName = "";
    std::string bundleName = "";
    std::string dataGroupId = "";
    std::shared_mutex opMutex_;
    int SetFileName(const std::string &str);
    void SetBundleName(const std::string &str);
    void SetDataGroupId(const std::string &str);
    std::string GetFileName();
    std::string GetBundleName();
    std::string GetDataGroupId();
};

class NDKPreferencesUtils {
public:
    static bool PreferencesStructValidCheck(int64_t cid, int64_t structCid);
};

#endif // PREFERENCES_STORE_IMPL_H