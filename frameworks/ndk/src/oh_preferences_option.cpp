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

#include "oh_preferences_option.h"

#include "log_print.h"
#include "oh_preferences_impl.h"
#include "oh_preferences_err_code.h"

using namespace OHOS::PreferencesNdk;

OH_PreferencesOption* OH_PreferencesOption_Create(void)
{
    return new (std::nothrow) OH_PreferencesOption();
}

int OH_PreferencesOption_SetFilePath(OH_PreferencesOption *option, const char *filePath)
{
    option->filePath = std::string(filePath);
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesOption_SetBundleName(OH_PreferencesOption *option, const char *bundleName)
{
    option->bundleName = std::string(bundleName);
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesOption_SetDataGroupId(OH_PreferencesOption *option, const char *dataGroupId)
{
    option->dataGroupId = std::string(dataGroupId);
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesOption_Destroy(OH_PreferencesOption* option)
{
    delete option;
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}
