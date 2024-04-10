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
#include "preferences_utils.h"

#include <string>

#include "log_print.h"
#include "preferences_errno.h"
#include "preferences_value.h"

namespace OHOS {
namespace NativePreferences {

std::string MakeFilePath(const std::string &prefPath, const std::string &suffix)
{
    return prefPath + suffix;
}

int CheckKey(const std::string &key)
{
    if (key.empty()) {
        LOG_ERROR("The key string is null or empty.");
        return E_KEY_EMPTY;
    }
    if (MAX_KEY_LENGTH < key.length()) {
        LOG_ERROR("The key string length should shorter than 80.");
        return E_KEY_EXCEED_MAX_LENGTH;
    }
    return E_OK;
}

int CheckValue(const PreferencesValue &value)
{
    auto lengthCheck = [] (uint32_t length, const std::string &errMsg) {
        if (MAX_VALUE_LENGTH < length) {
            LOG_ERROR("%{public}s", errMsg.c_str());
            return E_VALUE_EXCEED_MAX_LENGTH;
        }
        return E_OK;
    };

    if (value.IsString()) {
        std::string val = value;
        return lengthCheck(val.length(), "the value string length should shorter than 8 * 1024.");
    }

    if (value.IsObject()) {
        Object obj = value;
        return lengthCheck(obj.valueStr.length(), "the length of the object converted to JSON should be less than 8 *"
                                                  " 1024");
    }

    if (value.IsBigInt()) {
        BigInt bigint = value;
        if (bigint.words_.empty()) {
            LOG_ERROR("BigInt words cannot be empty.");
            return E_ERROR;
        }
        return E_OK;
    }
    return E_OK;
}
} // End of namespace NativePreferences
} // End of namespace OHOS
