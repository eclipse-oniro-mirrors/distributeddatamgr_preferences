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

#ifndef PREFERENCES_UTILS_H
#define PREFERENCES_UTILS_H

#include <string>

#include "preferences_value.h"

namespace OHOS {
namespace NativePreferences {
/**
* @brief The constant Indicates the maximum length of the key in the preferences.
*/
static constexpr uint32_t MAX_KEY_LENGTH = 80;
/**
 * @brief The constant Indicates the maximum length of the value in the preferences.
 */
static constexpr uint32_t MAX_VALUE_LENGTH = 8 * 1024;

static const char *STR_BROKEN = ".broken";
static const char *STR_BACKUP = ".bak";
static const char *STR_LOCK = ".lock";
static const char *STR_QUERY = "?";
static const char *STR_SLASH = "/";
static const char *STR_SCHEME = "sharepreferences://";

std::string MakeFilePath(const std::string &prefPath, const std::string &suffix);

int CheckKey(const std::string &key);

int CheckValue(const PreferencesValue &value);
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_H
