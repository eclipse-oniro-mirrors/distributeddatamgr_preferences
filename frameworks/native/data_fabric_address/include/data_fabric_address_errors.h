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

#ifndef DATA_FABRIC_ADDRESS_ERRORS_H
#define DATA_FABRIC_ADDRESS_ERRORS_H

#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "preferences_visibility.h"

namespace OHOS {
namespace NativePreferences {

constexpr int32_t RUN_OK { 0 };
constexpr int32_t PERMISSION_EXCEPTION { 201 };
constexpr int32_t NOT_SYSTEM_CALL { 202 };
constexpr int32_t DEVICE_EXCEPTION { 801 };
constexpr int32_t INTERNAL_EXCEPTION { 36900001 };
constexpr int32_t SUBSCRIBE_EXCEPTION { 36900002 };
constexpr int32_t UNSUBSCRIBE_EXCEPTION { 36900003 };
constexpr int32_t ABNORMAL_OPERATION_EXCEPTION { 36900004 };
constexpr int32_t PARAMETER_EXCEPTION { 36900005 };

const std::map<int32_t, std::string> ERROR_MESSAGES = {
    { PERMISSION_EXCEPTION, "Permission denied." },
    { NOT_SYSTEM_CALL, "Not system application." },
    { DEVICE_EXCEPTION,
        "Capability not supported. Function can not work correctly due to limited device capabilities." },
    { INTERNAL_EXCEPTION, "Internal error in the API." },
    { SUBSCRIBE_EXCEPTION, "Subscription failed." },
    { UNSUBSCRIBE_EXCEPTION, "Unsubscription failed." },
    { ABNORMAL_OPERATION_EXCEPTION, "Operation not supported." },
    { PARAMETER_EXCEPTION, "Invalid parameter." }
};

class DataFabricAddressErrors {
public:
    static PREF_API_EXPORT std::optional<std::string> GetErrMsg(int32_t errorCode);
private:
    DataFabricAddressErrors() = default;
    ~DataFabricAddressErrors() = default;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_ERRORS_H
