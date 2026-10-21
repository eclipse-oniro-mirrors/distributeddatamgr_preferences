/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "data_fabric_address_errors.h"

#include "log_print.h"

#undef LOG_TAG
#define LOG_TAG "DataFabricAddressErrors"

namespace OHOS {
namespace NativePreferences {

std::optional<std::string> DataFabricAddressErrors::GetErrMsg(int32_t errorCode)
{
    auto iter = ERROR_MESSAGES.find(errorCode);
    if (iter != ERROR_MESSAGES.end()) {
        return iter->second;
    }
    LOG_ERROR("Error, message not found");
    return std::nullopt;
}
} // End of namespace NativePreferences
} // End of namespace OHOS
