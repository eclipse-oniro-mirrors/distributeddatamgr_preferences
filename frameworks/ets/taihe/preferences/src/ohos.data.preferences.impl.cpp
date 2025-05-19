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
#include "ohos.data.preferences.impl.hpp"

#include "ani_ability.h"
#include "ani_common_utils.h"
#include "log_print.h"
#include "ohos.data.preferences.proj.hpp"
#include "preferences.h"
#include "preferences_helper.h"
#include "preferences_proxy.h"
#include "preferences_value.h"
#include "taihe/runtime.hpp"
#include "taihe_common_utils.h"
#include "taihe_preferences_error.h"
namespace {
using namespace taihe;
using namespace OHOS::NativePreferences;

using Preferences_t = ohos::data::preferences::Preferences;
using Options_t = ohos::data::preferences::Options;
using StorageType_t = ohos::data::preferences::StorageType;
using PreferencesProxy = OHOS::PreferencesEtsKit::PreferencesProxy;
using ParamTypeError = OHOS::PreferencesEtsKit::ParamTypeError;
using InnerError = OHOS::PreferencesEtsKit::InnerError;
using EtsError = OHOS::PreferencesEtsKit::EtsError;

static Preferences_t defaultPreferences = make_holder<PreferencesProxy, Preferences_t>();

struct PreferencesInfo {
    std::string path;
    std::string name;
    std::string bundleName;
    std::string dataGroupId;
    StorageType storageType = StorageType::XML;
    bool isStorageTypeSupported = false;
};

PreferencesInfo ParseOptions(Options_t const& options)
{
    PreferencesInfo preferencesInfo;
    preferencesInfo.name = std::string(options.name);
    if (options.dataGroupId.holds_stringType()) {
        preferencesInfo.dataGroupId = std::string(options.dataGroupId.get_stringType_ref());
    }
    if (options.storageType.holds_storageType()) {
        int32_t storageTypeVal = static_cast<int32_t>(options.storageType.get_storageType_ref());
        bool isValid = storageTypeVal == static_cast<int32_t>(StorageType::XML) ||
            storageTypeVal == static_cast<int32_t>(StorageType::GSKV);
        PRE_ANI_ASSERT_BASE(isValid, std::make_shared<ParamTypeError>("Storage type value invalid."), preferencesInfo);
        preferencesInfo.storageType = (storageTypeVal == static_cast<int32_t>(StorageType::XML)) ?
                StorageType::XML : StorageType::GSKV;
        }
    return preferencesInfo;
}

std::shared_ptr<EtsError> ParseContext(uintptr_t context, PreferencesInfo &preferencesInfo)
{
    auto env = ::taihe::get_env();
    OHOS::PreferencesEtsKit::EtsAbility::ContextInfo contextInfo;
    if (env == nullptr) {
        return std::make_shared<InnerError>("Failed to get env.");
    }
    auto err = GetContextInfo(env, reinterpret_cast<ani_object>(context), preferencesInfo.dataGroupId, contextInfo);
    if (err != nullptr) {
        return err;
    }
    preferencesInfo.path = contextInfo.preferencesDir.append("/").append(preferencesInfo.name);
    preferencesInfo.bundleName = contextInfo.bundleName;
    return nullptr;
}

Preferences_t GetPreferences(uintptr_t context, PreferencesInfo &info)
{
    auto err = ParseContext(context, info);
    PRE_ANI_ASSERT_BASE(err == nullptr, err, defaultPreferences);
    Options nativeOptions(info.path, info.bundleName, info.dataGroupId, info.storageType == StorageType::GSKV);
    int32_t errCode = OHOS::NativePreferences::E_OK;
    auto preferences = PreferencesHelper::GetPreferences(nativeOptions, errCode);
    PRE_ANI_ASSERT_BASE(errCode == OHOS::NativePreferences::E_OK, std::make_shared<InnerError>(errCode),
        defaultPreferences);
    return make_holder<PreferencesProxy, Preferences_t>(preferences);
}

Preferences_t GetPreferencesSync(uintptr_t context, Options_t const& options)
{
    auto preferencesInfo = ParseOptions(options);
    return GetPreferences(context, preferencesInfo);
}

Preferences_t GetPreferencesSyncByName(uintptr_t context, string_view name)
{
    PreferencesInfo preferencesInfo = {
        .name = std::string(name)
    };
    return GetPreferences(context, preferencesInfo);
}

void DeletePreferences(uintptr_t context, PreferencesInfo &info)
{
    auto err = ParseContext(context, info);
    PRE_ANI_ASSERT_RETURN_VOID(err == nullptr, err);
    auto errCode = PreferencesHelper::DeletePreferences(info.path);
    PRE_ANI_ASSERT_RETURN_VOID(errCode == OHOS::NativePreferences::E_OK, std::make_shared<InnerError>(errCode));
}

void DeletePreferencesSync(uintptr_t context, Options_t const& options)
{
    auto preferencesInfo = ParseOptions(options);
    DeletePreferences(context, preferencesInfo);
}

void DeletePreferencesSyncByName(uintptr_t context, string_view name)
{
    PreferencesInfo preferencesInfo = {
        .name = std::string(name)
    };
    DeletePreferences(context, preferencesInfo);
}

void RemovePreferencesFromCache(uintptr_t context, PreferencesInfo &info)
{
    auto err = ParseContext(context, info);
    PRE_ANI_ASSERT_RETURN_VOID(err == nullptr, err);
    auto errCode = PreferencesHelper::RemovePreferencesFromCache(info.path);
    PRE_ANI_ASSERT_RETURN_VOID(errCode == OHOS::NativePreferences::E_OK, std::make_shared<InnerError>(errCode));
}

void RemovePreferencesFromCacheSync(uintptr_t context, string_view name) {
    PreferencesInfo preferencesInfo = {
        .name = std::string(name)
    };
    RemovePreferencesFromCache(context, preferencesInfo);
}

void RemovePreferencesFromCacheSyncByOptions(uintptr_t context, Options_t const& options)
{
    auto preferencesInfo = ParseOptions(options);
    RemovePreferencesFromCache(context, preferencesInfo);
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_GetPreferencesSync(GetPreferencesSync);
TH_EXPORT_CPP_API_GetPreferencesSyncByName(GetPreferencesSyncByName);
TH_EXPORT_CPP_API_DeletePreferencesSync(DeletePreferencesSync);
TH_EXPORT_CPP_API_DeletePreferencesSyncByName(DeletePreferencesSyncByName);
TH_EXPORT_CPP_API_RemovePreferencesFromCacheSync(RemovePreferencesFromCacheSync);
TH_EXPORT_CPP_API_RemovePreferencesFromCacheSyncByOptions(RemovePreferencesFromCacheSyncByOptions);
// NOLINTEND
