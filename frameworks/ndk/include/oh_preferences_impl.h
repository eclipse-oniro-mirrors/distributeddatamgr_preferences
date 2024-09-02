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

#ifdef __cplusplus
extern "C" {
#endif

class NDKPreferencesObserver : public OHOS::NativePreferences::PreferencesObserver {
public:
    NDKPreferencesObserver(const OH_PreferencesDataObserver *observer, void *context);
    ~NDKPreferencesObserver() noexcept override = default;

    void OnChange(const std::string &key) override;
    void OnChange(const std::map<std::string, OHOS::NativePreferences::PreferencesValue> &records) override;

    bool operator==(const OH_PreferencesDataObserver *other);

private:
    const OH_PreferencesDataObserver *dataObserver_;
    void *context_;
};

struct OH_Preferences {
    int id;
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
        const OH_PreferencesDataObserver *observer, void *context, const std::vector<std::string> &keys = {});
    int UnRegisterDataObserver(const OH_PreferencesDataObserver *observer, const std::vector<std::string> &keys = {});

    void SetPreferencesStoreFilePath(const std::string &filePath);
    std::string GetPreferencesStoreFilePath();

private:
    std::shared_ptr<OHOS::NativePreferences::Preferences> preferences_;
    std::shared_mutex mutex_;
    std::string filePath_ = "";
    std::shared_mutex obsMutex_;
    std::vector<std::shared_ptr<NDKPreferencesObserver>> dataObservers_;
};

struct OH_PreferencesOption {
    std::string filePath;
    std::string bundleName;
    std::string dataGroupId;
};

#ifdef __cplusplus
}
#endif
#endif // PREFERENCES_STORE_IMPL_H