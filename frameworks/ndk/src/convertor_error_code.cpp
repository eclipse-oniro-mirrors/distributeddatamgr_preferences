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
#include <map>
#include "convertor_error_code.h"
#include "oh_preferences_err_code.h"
#include "preferences_errno.h"

namespace OHOS::PreferencesNdk {

struct NdkErrCode {
    int nativeCode;
    int ndkCode;
};

const std::map<int, int> ERROR_CODE_MAP = {
    { OHOS::NativePreferences::E_OK, OH_Preferences_ErrCode::PREFERENCES_OK },
    { OHOS::NativePreferences::E_INVALID_ARGS, OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM },
    { OHOS::NativePreferences::E_NOT_SUPPORTED, OH_Preferences_ErrCode::PREFERENCES_ERROR_NOT_SUPPORTED },
    { OHOS::NativePreferences::E_DELETE_FILE_FAIL, OH_Preferences_ErrCode::PREFERENCES_ERROR_DELETE_FILE },
    { OHOS::NativePreferences::E_GET_DATAOBSMGRCLIENT_FAIL,
        OH_Preferences_ErrCode::PREFERENCES_ERROR_GET_DATAOBSMGRCLIENT }
};

int ConvertorErrorCode::NativeErrToNdk(int nativeCode)
{
    auto iter = ERROR_CODE_MAP.find(nativeCode);
    if (iter != ERROR_CODE_MAP.end()) {
        return iter->second;
    }
    return PREFERENCES_ERROR_STORAGE;
}
}