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
#include "preferences_error.h"

namespace OHOS {
namespace PreferencesJsKit {

static constexpr JsErrorCode JS_ERROR_MAPS[] = {
    { E_NOT_STAGE_MODE, E_NOT_STAGE_MODE, "The operations is supported in stage mode only." },
    { E_DATA_GROUP_ID_INVALID, E_DATA_GROUP_ID_INVALID, "Invalid dataGroupId." },
    { NativePreferences::E_INVALID_ARGS, E_INNER_ERROR, "Invalid arguments." },
    { NativePreferences::E_KEY_EMPTY, E_INNER_ERROR, "The key is empty." },
    { NativePreferences::E_KEY_EXCEED_MAX_LENGTH, E_INNER_ERROR,
        "The key length exceeds 1024 characters." },
    { NativePreferences::E_RELATIVE_PATH, E_INNER_ERROR, "Relative path is not allowed." },
    { NativePreferences::E_EMPTY_FILE_PATH, E_INNER_ERROR, "The file path is empty." },
    { NativePreferences::E_DELETE_FILE_FAIL, E_DELETE_FILE_FAIL,
        "Failed to delete the user preferences persistence file." },
    { NativePreferences::E_EMPTY_FILE_NAME, E_INNER_ERROR, "The file name is empty." },
    { NativePreferences::E_INVALID_FILE_PATH, E_INNER_ERROR, "Invalid file path." },
    { NativePreferences::E_PATH_EXCEED_MAX_LENGTH, E_INNER_ERROR,
        "The file path length exceeds the limit." },
    { NativePreferences::E_VALUE_EXCEED_MAX_LENGTH, E_INNER_ERROR,
        "The value length exceeds 16 MB." },
    { NativePreferences::PERMISSION_DENIED, E_INNER_ERROR, "Permission denied." },
    { NativePreferences::E_GET_DATAOBSMGRCLIENT_FAIL, E_GET_DATAOBSMGRCLIENT_FAIL,
        "Failed to obtain the subscription service." },
    { NativePreferences::E_ALREADY_CLOSED, E_INNER_ERROR, "The database has been closed." },
    { NativePreferences::E_NOT_SUPPORTED, E_NOT_SUPPORTED, "Capability not supported." },
};

static constexpr bool IsIncreasing()
{
    for (size_t i = 1; i < sizeof(JS_ERROR_MAPS) / sizeof(JSErrorCode); i++) {
        if (JS_ERROR_MAPS[i].nativeCode <= JS_ERROR_MAPS[i - 1].nativeCode) {
            return false;
        }
    }
    return true;
}

static_assert(IsIncreasing(), "JS_ERROR_MAPS must be in increasing order by nativeCode");

const std::optional<JsErrorCode> GetJsErrorCode(int32_t errorCode)
{
    auto jsErrorCode = JsErrorCode{ errorCode, -1, "" };
    auto iter = std::lower_bound(JS_ERROR_MAPS, JS_ERROR_MAPS + sizeof(JS_ERROR_MAPS) / sizeof(JS_ERROR_MAPS[0]),
        jsErrorCode, [](const JsErrorCode &jsErrorCode1, const JsErrorCode &jsErrorCode2) {
            return jsErrorCode1.nativeCode < jsErrorCode2.nativeCode;
        });
    if (iter < JS_ERROR_MAPS + sizeof(JS_ERROR_MAPS) / sizeof(JS_ERROR_MAPS[0]) && iter->nativeCode == errorCode) {
        return *iter;
    }
    return std::nullopt;
}

} // namespace PreferencesJsKit
} // namespace OHOS
