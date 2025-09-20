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

#include "dbpreferences_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_helper.h"

using namespace OHOS::NativePreferences;

namespace OHOS {
class DBPreferencesFuzzTest {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::shared_ptr<Preferences> preferences_;
};

std::shared_ptr<Preferences> DBPreferencesFuzzTest::preferences_ = nullptr;

void DBPreferencesFuzzTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    Options option = {"/data/test/test", "", "", true};
    preferences_ = PreferencesHelper::GetPreferences(option, errCode);
}

void DBPreferencesFuzzTest::TearDownTestCase(void)
{
    preferences_->Clear();
    PreferencesHelper::RemovePreferencesFromCache("/data/test/test");
    preferences_ = nullptr;
}

void DBPreferencesFuzzTest::SetUp(void)
{
}

void DBPreferencesFuzzTest::TearDown(void)
{
}

void GetAllFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesFuzzTest::preferences_->PutInt(key, value);
    DBPreferencesFuzzTest::preferences_->GetAll();
    return;
}

void GetAllDataFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesFuzzTest::preferences_->PutInt(key, value);
    DBPreferencesFuzzTest::preferences_->GetAllData();
    return;
}

void GetAllDatasFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesFuzzTest::preferences_->PutInt(key, value);
    DBPreferencesFuzzTest::preferences_->GetAllDatas();
    return;
}

void DeleteFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesFuzzTest::preferences_->PutLong(key, value);
    DBPreferencesFuzzTest::preferences_->Delete(key);
    return;
}

void ClearFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesFuzzTest::preferences_->PutLong(key, value);
    DBPreferencesFuzzTest::preferences_->Clear();
    return;
}

void FlushFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesFuzzTest::preferences_->PutLong(key, value);
    DBPreferencesFuzzTest::preferences_->Flush();
    DBPreferencesFuzzTest::preferences_->GetLong(key);
    PreferencesHelper::DeletePreferences("/data/test/test");
    return;
}

void FlushSyncFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesFuzzTest::preferences_->PutLong(key, value);
    DBPreferencesFuzzTest::preferences_->FlushSync();
    DBPreferencesFuzzTest::preferences_->GetLong(key);
    PreferencesHelper::DeletePreferences("/data/test/test");
    return;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::DBPreferencesFuzzTest::SetUpTestCase();
    OHOS::GetAllFuzz(provider);
    OHOS::GetAllDataFuzz(provider);
    OHOS::GetAllDatasFuzz(provider);
    OHOS::DeleteFuzz(provider);
    OHOS::ClearFuzz(provider);
    OHOS::FlushFuzz(provider);
    OHOS::FlushSyncFuzz(provider);
    OHOS::DBPreferencesFuzzTest::TearDownTestCase();
    return 0;
}