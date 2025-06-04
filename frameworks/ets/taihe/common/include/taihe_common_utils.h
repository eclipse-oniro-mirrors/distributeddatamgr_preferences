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

#ifndef PREFERENCES_FRAMEWORKS_TAIHE_UTILS_H
#define PREFERENCES_FRAMEWORKS_TAIHE_UTILS_H

#include <map>

#include "napi_preferences_error.h"
#include "ohos.data.preferences.proj.hpp"
#include "preferences_value.h"
#include "taihe/runtime.hpp"

namespace OHOS {
namespace PreferencesEtsKit {
namespace EtsUtils {
using ValueTypeT = ohos::data::preferences::ValueType;
using TypesInArrayT = ohos::data::preferences::TypesInArray;

NativePreferences::PreferencesValue ConvertToPreferencesValue(const ValueTypeT &value);

ValueTypeT ConvertToValueType(const NativePreferences::PreferencesValue &value);

::taihe::map<::taihe::string, ValueTypeT> ConvertMapToTaiheMap(
    const std::map<std::string, NativePreferences::PreferencesValue> &records);

void SetBusinessError(std::shared_ptr<PreferencesJsKit::JSError> error);
} // namespace EtsUtils
} // namespace PreferencesEtsKit
} // namespace OHOS

#endif // PREFERENCES_FRAMEWORKS_TAIHE_UTILS_H
