/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "base64_helper.h"
#include <vector>
#include "log_print.h"

namespace OHOS {
namespace NativePreferences {
static const uint8_t base64Encoder[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const uint8_t base64Decoder[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62,  -1, -1, -1, 63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  -1, -1, -1, -1, -1, -1,
    -1, 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,
    15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  -1, -1, -1, -1, -1,
    -1, 26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
    41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

const uint32_t BASE64_DEST_UNIT_SIZE = 4;
const uint32_t BASE64_SRC_UNIT_SIZE = 3;
const uint32_t BASE64_ONE_PADDING = 1;
const uint32_t BASE64_TWO_PADDING = 2;
const uint8_t BASE64_INVALID = 0xFF;
const uint8_t BASE64_MASK1 = 0x03;
const uint8_t BASE64_MASK2 = 0x0F;
const uint8_t BASE64_MASK3 = 0x3F;
const uint8_t BASE64_SHIFT_HIBYTE = 2;
const uint8_t BASE64_SHIFT = 4;
const uint8_t BASE64_SHIFT_LOBYTE = 6;

std::string Base64Helper::Encode(const std::vector<uint8_t> &input)
{
    std::string result = "";
    uint32_t index = 0;
    for (uint32_t len = input.size(); len > 0; len -= BASE64_SRC_UNIT_SIZE) {
        result += base64Encoder[input.at(index) >> BASE64_SHIFT_HIBYTE];
        uint8_t code = (input.at(index++) & BASE64_MASK1) << BASE64_SHIFT;
        if (len > BASE64_ONE_PADDING) {
            result += base64Encoder[code | (input.at(index) >> BASE64_SHIFT)];
            code = (input.at(index++) & BASE64_MASK2) << BASE64_SHIFT_HIBYTE;
            if (len > BASE64_TWO_PADDING) {
                result += base64Encoder[code | (input.at(index) >> BASE64_SHIFT_LOBYTE)];
                result += base64Encoder[input.at(index++) & BASE64_MASK3];
            } else {
                result += base64Encoder[code];
                result += "=";
                break;
            }
        } else {
            result += base64Encoder[code];
            result += "==";
            break;
        }
    }
    return result;
}

bool Base64Helper::Decode(const std::string &input, std::vector<uint8_t> &output)
{
    if (input.length() % BASE64_DEST_UNIT_SIZE != 0) {
        return false;
    }
    uint32_t index = 0;
    std::vector<uint8_t> result {};
    while (index < input.length()) {
        uint8_t ch1 = base64Decoder[static_cast<uint8_t>(input.at(index++))];
        uint8_t ch2 = base64Decoder[static_cast<uint8_t>(input.at(index++))];
        if (ch1 == BASE64_INVALID || ch2 == BASE64_INVALID) {
            return false;
        }
        result.emplace_back((ch1 << BASE64_SHIFT_HIBYTE) | (ch2 >> BASE64_SHIFT));
        if (input.at(index) == '=') {
            break;
        }
        uint8_t ch3 = base64Decoder[static_cast<uint8_t>(input.at(index++))];
        if (ch3 == BASE64_INVALID) {
            return false;
        }
        result.emplace_back((ch2 << BASE64_SHIFT) | (ch3 >> BASE64_SHIFT_HIBYTE));
        if (input.at(index) == '=') {
            break;
        }
        uint8_t ch4 = base64Decoder[static_cast<uint8_t>(input.at(index++))];
        if (ch4 == BASE64_INVALID) {
            return false;
        }
        result.emplace_back((ch3 << BASE64_SHIFT_LOBYTE) | ch4);
    }
    output = result;
    return true;
}
} // End of namespace NativePreferences
} // End of namespace OHOS
