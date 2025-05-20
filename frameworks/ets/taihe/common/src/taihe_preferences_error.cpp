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
#include "taihe_preferences_error.h"

#include "log_print.h"
#include "taihe/runtime.hpp"

namespace OHOS {
namespace PreferencesEtsKit {

static constexpr EtsErrorCode ETS_ERROR_MAPS[] = {
    { E_NOT_STAGE_MODE, E_NOT_STAGE_MODE, "Only supported in stage mode" },
    { E_DATA_GROUP_ID_INVALID, E_DATA_GROUP_ID_INVALID, "The data group id is not valid" },
    { NativePreferences::E_DELETE_FILE_FAIL, E_DELETE_FILE_FAIL, "Failed to delete preferences file." },
    { NativePreferences::E_GET_DATAOBSMGRCLIENT_FAIL, E_GET_DATAOBSMGRCLIENT_FAIL,
        "Failed to obtain subscription service." },
    { NativePreferences::E_NOT_SUPPORTED, E_NOT_SUPPORTED, "Capability not supported" },
};

const std::optional<EtsErrorCode> GetEtsErrorCode(int32_t errorCode)
{
    auto etsErrorCode = EtsErrorCode{ errorCode, -1, "" };
    auto iter = std::lower_bound(ETS_ERROR_MAPS, ETS_ERROR_MAPS + sizeof(ETS_ERROR_MAPS) / sizeof(ETS_ERROR_MAPS[0]),
        etsErrorCode, [](const EtsErrorCode &jsErrorCode1, const EtsErrorCode &jsErrorCode2) {
            return jsErrorCode1.nativeCode < jsErrorCode2.nativeCode;
        });
    if (iter < ETS_ERROR_MAPS + sizeof(ETS_ERROR_MAPS) / sizeof(ETS_ERROR_MAPS[0]) && iter->nativeCode == errorCode) {
        return *iter;
    }
    return std::nullopt;
}

void SetBusinessError(std::shared_ptr<EtsError> error)
{
    LOG_ERROR("throw error: code=%{public}d, message=%{public}s", error->GetCode(), error->GetMsg().c_str());
    ::taihe::set_business_error(error->GetCode(), error->GetMsg().c_str());
}

} // namespace PreferencesEtsKit
} // namespace OHOS
