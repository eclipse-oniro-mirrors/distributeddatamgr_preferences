/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef PREFERENCES_FRAMEWORKS_TAIHE_PREFERENCES_PROXY_H
#define PREFERENCES_FRAMEWORKS_TAIHE_PREFERENCES_PROXY_H

#include <list>

#include "ohos.data.preferences.impl.hpp"
#include "ohos.data.preferences.proj.hpp"
#include "preferences.h"
#include "preferences_value.h"
#include "taihe/runtime.hpp"
#include "taihe_common_utils.h"
#include "taihe_preferences_observer.h"

namespace OHOS {
namespace PreferencesEtsKit {
using namespace NativePreferences;
using namespace taihe;
using ValueType_t = ohos::data::preferences::ValueType;
class PreferencesProxy {
public:
    PreferencesProxy();

    PreferencesProxy(std::shared_ptr<Preferences> preferences);

    ValueType_t GetSync(string_view key, ValueType_t const& defValue);

    uintptr_t GetAllSync();

    bool HasSync(string_view key);

    void PutSync(string_view key, ValueType_t const& value);

    void DeleteSync(string_view key);

    void ClearSync();

    void FlushSync();

    void OnChange(callback_view<void(string_view)> cb, uintptr_t opq);

    void OffChange(optional_view<uintptr_t> opq);

    void OnMultiProcessChange(callback_view<void(string_view)> cb, uintptr_t opq);

    void OffMultiProcessChange(optional_view<uintptr_t> opq);

    void OnDataChange(array_view<string> keys, callback_view<void(map_view<string, ValueType_t>)> cb, uintptr_t opq);

    void OffDataChange(array_view<string> keys, optional_view<uintptr_t> opq);

    virtual ~PreferencesProxy();
private:
    ani_ref CreateGlobalReference(ani_env *env, uintptr_t opq);

    void RegisteredObserver(RegisterMode mode, CallbackType callback, uintptr_t opq);

    void RegisteredDataObserver(const std::vector<std::string> &keys, CallbackType callback, uintptr_t opq);

    bool HasRegisteredObserver(ani_env *env, ani_ref callbackRef, RegisterMode mode);

    void UnRegisteredObserver(RegisterMode mode, uintptr_t opq);

    void UnRegisteredAllObservers(RegisterMode mode);

    void UnRegisteredDataObserver(const std::vector<std::string> &keys, uintptr_t opq);

    void UnRegisteredAllDataObserver(const std::vector<std::string> &keys);

    bool CheckKey(const std::string &key);

    bool CheckValue(const std::string &value);

    std::shared_ptr<Preferences> preferences_;

    std::mutex listMutex_ {};
    std::list<std::shared_ptr<TaihePreferencesObserver>> localObservers_;
    std::list<std::shared_ptr<TaihePreferencesObserver>> multiProcessObservers_;
    std::list<std::shared_ptr<TaihePreferencesObserver>> dataObservers_;
};
} // namespace PreferencesEtsKit
} // namespace OHOS

#endif // PREFERENCES_FRAMEWORKS_TAIHE_PREFERENCES_PROXY_H