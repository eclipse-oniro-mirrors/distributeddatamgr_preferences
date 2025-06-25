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

#include "ndkpreferences_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

#include "oh_preferences.h"
#include "oh_preferences_err_code.h"
#include "oh_preferences_value.h"
#include "oh_preferences_option.h"
#include "preferences.h"
#include "preferences_file_operation.h"

using namespace OHOS::NativePreferences;

namespace OHOS {
class NdkPreferencesFuzzTest {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static void CreateDirectoryRecursively(const std::string &path);
};

void NdkPreferencesFuzzTest::SetUpTestCase(void)
{
    CreateDirectoryRecursively("/data/test/");
}

void NdkPreferencesFuzzTest::TearDownTestCase(void)
{
}

void NdkPreferencesFuzzTest::SetUp(void)
{
    CreateDirectoryRecursively("/data/test/");
}

void NdkPreferencesFuzzTest::TearDown(void)
{
}

void NdkPreferencesFuzzTest::CreateDirectoryRecursively(const std::string &path)
{
    std::string::size_type pos = path.find_last_of('/');
    if (pos == std::string::npos || path.front() != '/') {
        printf("path can not be relative path.\n");
    }
    std::string dir = path.substr(0, pos);

    std::string tempDirectory = dir;
    std::vector<std::string> directories;

    pos = tempDirectory.find('/');
    while (pos != std::string::npos) {
        std::string directory = tempDirectory.substr(0, pos);
        if (!directory.empty()) {
            directories.push_back(directory);
        }
        tempDirectory = tempDirectory.substr(pos + 1);
        pos = tempDirectory.find('/');
    }
    directories.push_back(tempDirectory);

    std::string databaseDirectory;
    for (const std::string& directory : directories) {
        databaseDirectory = databaseDirectory + "/" + directory;
        if (OHOS::NativePreferences::Access(databaseDirectory.c_str()) != F_OK) {
            if (OHOS::NativePreferences::Mkdir(databaseDirectory)) {
                printf("failed to mkdir, errno %d, %s \n", errno, databaseDirectory.c_str());
                return;
            }
        }
    }
}

void PutIntFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    OH_PreferencesOption_SetFileName(option, "test");
    int32_t errCode = 0;
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    OH_Preferences_SetInt(pref, key.c_str(), value);
    (void)OH_PreferencesOption_Destroy(option);
    OH_Preferences_Close(pref);
    return;
}

void GetIntFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    OH_PreferencesOption_SetFileName(option, "test");
    int32_t errCode = 0;
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_Preferences_SetInt(pref, key.c_str(), value);
    int values = 10;
    OH_Preferences_GetInt(pref, key.c_str(), &values);
    (void)OH_PreferencesOption_Destroy(option);
    OH_Preferences_Close(pref);
    return;
}

void PutStringFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    std::string value = provider.ConsumeRandomLengthString();
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    OH_PreferencesOption_SetFileName(option, "test");
    int32_t errCode = 0;
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    OH_Preferences_SetString(pref, key.c_str(), value.c_str());
    (void)OH_PreferencesOption_Destroy(option);
    OH_Preferences_Close(pref);
    return;
}

void GetStringFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    std::string value = provider.ConsumeRandomLengthString();
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    OH_PreferencesOption_SetFileName(option, "test");
    int32_t errCode = 0;
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_Preferences_SetString(pref, key.c_str(), value.c_str());
    (void)OH_PreferencesOption_Destroy(option);
    uint32_t len = 0;
    char *values = nullptr;
    OH_Preferences_GetString(pref, key.c_str(), &values, &len);
    OH_Preferences_FreeString(values);
    (void)OH_Preferences_Close(pref);
    return;
}

void PutBoolFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeBool();
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    OH_PreferencesOption_SetFileName(option, "test");
    int32_t errCode = 0;
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    OH_Preferences_SetBool(pref, key.c_str(), value);
    (void)OH_PreferencesOption_Destroy(option);
    OH_Preferences_Close(pref);
    return;
}

void GetBoolFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeBool();
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    OH_PreferencesOption_SetFileName(option, "test");
    int32_t errCode = 0;
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_Preferences_SetBool(pref, key.c_str(), value);
    (void)OH_PreferencesOption_Destroy(option);
    bool values = false;
    OH_Preferences_GetBool(pref, key.c_str(), &values);
    OH_Preferences_Close(pref);
    return;
}

void DeleteFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeBool();
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    OH_PreferencesOption_SetFileName(option, "test");
    int32_t errCode = 0;
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_Preferences_SetBool(pref, key.c_str(), value);
    (void)OH_PreferencesOption_Destroy(option);
    OH_Preferences_Delete(pref, key.c_str());
    OH_Preferences_Close(pref);
    return;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::NdkPreferencesFuzzTest::SetUpTestCase();
    OHOS::PutIntFuzz(provider);
    OHOS::GetIntFuzz(provider);
    OHOS::PutStringFuzz(provider);
    OHOS::GetStringFuzz(provider);
    OHOS::PutBoolFuzz(provider);
    OHOS::GetBoolFuzz(provider);
    OHOS::DeleteFuzz(provider);
    OHOS::NdkPreferencesFuzzTest::TearDownTestCase();
    return 0;
}