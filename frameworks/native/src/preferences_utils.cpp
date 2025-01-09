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
        LOG_ERROR("The key string length should shorter than 1024.");
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
        return lengthCheck(val.length(), "the value string length should shorter than 16 * 1024 * 1024.");
    }

    if (value.IsObject()) {
        Object obj = value;
        return lengthCheck(obj.valueStr.length(), "the length of the object converted to JSON should be less than 16 *"
                                                  " 1024 * 1024");
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

bool IsUtf8(const std::string &str)
{
    if (str.empty()) {
        return true;
    }
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(str.c_str());
    int32_t num;
    while (*bytes != 0x00) {
        // 判断几字节编码
        if ((*bytes & 0x80) == 0x00) {
            num = UTF8_BYTE_NUM_ONE; // U+0000 to U+007F
        } else if ((*bytes & 0xE0) == 0xC0) {
            num = UTF8_BYTE_NUM_TWO; // U+0080 to U+07FF
        } else if ((*bytes & 0xF0) == 0xE0) {
            num = UTF8_BYTE_NUM_THREE; // U+0800 to U+FFFF
        } else if ((*bytes & 0xF8) == 0xF0) {
            num = UTF8_BYTE_NUM_FOUR; // U+10000 to U+10FFFF
        } else {
            return false;
        }
        ++bytes;
        // 除第一字节其他字节均为10开头 11110XXX 10XXXXXX 10XXXXXX 10XXXXXX
        for (int i = 1; i < num; i++) {
            if ((*bytes & 0xC0) != 0x80) {
                return false;
            }
            ++bytes;
        }
    }
    return true;
}
} // End of namespace NativePreferences
} // End of namespace OHOS
