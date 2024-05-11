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

#ifndef PREFERENCES_JSKIT_NAPI_PREFERENCE_H
#define PREFERENCES_JSKIT_NAPI_PREFERENCE_H

#include <assert.h>

#include <list>
#include <set>

#include "js_observer.h"
#include "js_proxy.h"
#include "js_utils.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_preferences_observer.h"
#include "preferences.h"
#include "preferences_helper.h"

namespace OHOS::Sendable::JSPreferences {
using RegisterMode = NativePreferences::PreferencesObserver::RegisterMode;
using JSPreferencesObserver = PreferencesJsKit::JSPreferencesObserver;
using UvQueue = PreferencesJsKit::UvQueue;
using Preferences = NativePreferences::Preferences;
template<typename T>
using JSProxy = OHOS::JSProxy::JSProxy<T>;
class PreferencesProxy : public JSProxy<Preferences> {
public:
    static void Init(napi_env env, napi_value exports);
    static napi_value New(napi_env env, napi_callback_info info);
    static napi_status NewInstance(napi_env env, std::shared_ptr<Preferences> value, napi_value *instance);
    static void Destructor(napi_env env, void *nativeObject, void *finalize_hint);

private:
    static constexpr char STR_CHANGE[] = "change";
    static constexpr char STR_MULTI_PRECESS_CHANGE[] = "multiProcessChange";
    static constexpr const char *STR_DATA_CHANGE = "dataChange";
    using Observer = NativePreferences::PreferencesObserver;
    using JSObserverImpl = JSPreferencesObserver;
    explicit PreferencesProxy();
    ~PreferencesProxy();

    static napi_value GetValue(napi_env env, napi_callback_info info);
    static napi_value SetValue(napi_env env, napi_callback_info info);
    static napi_value HasKey(napi_env env, napi_callback_info info);
    static napi_value Delete(napi_env env, napi_callback_info info);
    static napi_value Flush(napi_env env, napi_callback_info info);
    static napi_value Clear(napi_env env, napi_callback_info info);
    static napi_value RegisterObserver(napi_env env, napi_callback_info info);
    static napi_value UnregisterObserver(napi_env env, napi_callback_info info);
    static napi_value GetAll(napi_env env, napi_callback_info info);

    static std::pair<PreferencesProxy *, std::weak_ptr<Preferences>> GetSelfInstance(napi_env env, napi_value self);

    static RegisterMode ConvertToRegisterMode(const std::string &mode);

    int RegisteredObserver(napi_env env, napi_value callback, RegisterMode mode, const std::vector<std::string> &keys);
    int UnregisteredObserver(
        napi_env env, napi_value callback, RegisterMode mode, const std::vector<std::string> &keys);

    class JSObservers {
    public:
        JSObservers(napi_env env, PreferencesProxy *proxy);
        ~JSObservers();
        int Subscribe(napi_value callback, RegisterMode mode, const std::vector<std::string> &keys);
        int Unsubscribe(napi_value callback, RegisterMode mode, const std::vector<std::string> &keys);
    private:
        static void CleanEnv(void *obj);

        std::shared_ptr<UvQueue> uvQueue_;
        std::list<std::shared_ptr<JSObserverImpl>> observers_[Observer::CHANGE_BUTT];
        napi_env env_ = nullptr;
        PreferencesProxy *proxy_ = nullptr;
    };
    std::mutex mutex_{};
    std::map<napi_env, JSObservers> observers_;
};
} // namespace OHOS::Sendable::Preferences
#endif // PREFERENCES_JSKIT_NAPI_PREFERENCE_H
