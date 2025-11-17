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
#ifndef PREFERENCES_IMPL_H
#define PREFERENCES_IMPL_H

#include <string>
#include <list>
#include "preferences.h"
#include "preferences_interface.h"
#include "ffi_remote_data.h"
#include "preferences_observer.h"

#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM)
namespace OHOS {
namespace AbilityRuntime {
    typedef void Context;
}
}
#else
#include "ability_context.h"
#endif

namespace OHOS {
namespace Preferences {
using RegisterMode = NativePreferences::PreferencesObserver::RegisterMode;

class CJPreferencesObserver : public OHOS::NativePreferences::PreferencesObserver {
public:
    CJPreferencesObserver(std::function<void(std::string)> *callback,
        const std::function<void(std::string)>& callbackRef);
    void OnChange(const std::string &key) override;
    std::function<void(std::string)> *m_callback;
    std::function<void(std::string)> m_callbackRef;
};

class PreferencesImpl : public OHOS::FFI::FFIData {
public:
    explicit PreferencesImpl(OHOS::AbilityRuntime::Context* context,
        const std::string& name, const std::string& dataGroupId, int32_t* errCode);

    static int32_t DeletePreferences(OHOS::AbilityRuntime::Context* context, const std::string &name,
        const std::string &dataGroupId);
    
    static int32_t RemovePreferencesFromCache(OHOS::AbilityRuntime::Context* context, const std::string &name,
        const std::string &dataGroupId);

    int32_t Delete(const std::string &key);

    bool HasKey(const std::string &key);

    bool HasRegisteredObserver(std::function<void(std::string)> *callback, RegisterMode mode);

    int32_t RegisterObserver(const std::string &mode, std::function<void(std::string)> *callback,
        const std::function<void(std::string)>& callbackRef);

    int32_t UnRegisterObserver(const std::string &mode, std::function<void(std::string)> *callback);

    int32_t UnRegisteredAllObservers(const std::string &mode);

    RegisterMode ConvertToRegisterMode(const std::string &mode);

    ValueType Get(const std::string &key, const ValueType &defValue);

    int32_t Put(const std::string &key, const ValueType &value);

    ValueTypes GetAll();

    void Flush();

    void Clear();

    OHOS::FFI::RuntimeType* GetRuntimeType() override;

private:
    friend class OHOS::FFI::TypeBase;
    friend class OHOS::FFI::RuntimeType;
    static OHOS::FFI::RuntimeType* GetClassType();
    static constexpr char strChange[] = "change";
    static constexpr char strMultiProcessChange[] = "multiProcessChange";
    std::shared_ptr<NativePreferences::Preferences> preferences;
    std::mutex listMutex_ {};
    std::list<std::shared_ptr<CJPreferencesObserver>> localObservers_;
    std::list<std::shared_ptr<CJPreferencesObserver>> multiProcessObservers_;
};
}
} // namespace OHOS::Preferences

#endif // PREFERENCES_IMPL_h