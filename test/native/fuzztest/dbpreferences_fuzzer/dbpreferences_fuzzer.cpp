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
constexpr size_t NUM_MIN = 1;
constexpr size_t NUM_MAX = 32 * 1024 * 1024;
class DBPreferencesFuzzTest {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::shared_ptr<Preferences> Preferences_;
};

std::shared_ptr<Preferences> DBPreferencesFuzzTest::Preferences_ = nullptr;

void DBPreferencesFuzzTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    Options option = {"/data/test/test", "", "", true};
    Preferences_ = PreferencesHelper::GetPreferences(option, errCode);
}

void DBPreferencesFuzzTest::TearDownTestCase(void)
{
    Preferences_->Clear();
    PreferencesHelper::RemovePreferencesFromCache("/data/test/test");
    Preferences_ = nullptr;
}

void DBPreferencesFuzzTest::SetUp(void)
{
}

void DBPreferencesFuzzTest::TearDown(void)
{
}

void PutVectorFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(NUM_MIN, NUM_MAX);
    std::vector<uint8_t> value = provider.ConsumeBytes<uint8_t>(bytesSize);
    DBPreferencesFuzzTest::Preferences_->Put(key, value);
    return;
}

void GetVectorFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(NUM_MIN, NUM_MAX);
    std::vector<uint8_t> value = provider.ConsumeBytes<uint8_t>(bytesSize);
    DBPreferencesFuzzTest::Preferences_->Put(key, value);
    DBPreferencesFuzzTest::Preferences_->Get(key, 0);
    return;
}

void HasFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesFuzzTest::Preferences_->PutInt(key, value);
    DBPreferencesFuzzTest::Preferences_->HasKey(key);
    return;
}

void GetValueFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesFuzzTest::Preferences_->PutInt(key, value);
    DBPreferencesFuzzTest::Preferences_->GetValue(key, 0);
    return;
}

void GetAllFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesFuzzTest::Preferences_->PutInt(key, value);
    DBPreferencesFuzzTest::Preferences_->GetAll();
    return;
}

void GetAllDataFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesFuzzTest::Preferences_->PutInt(key, value);
    DBPreferencesFuzzTest::Preferences_->GetAllData();
    return;
}

void GetAllDatasFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesFuzzTest::Preferences_->PutInt(key, value);
    DBPreferencesFuzzTest::Preferences_->GetAllDatas();
    return;
}

void PutIntFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesFuzzTest::Preferences_->PutInt(key, value);
    return;
}

void GetIntFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesFuzzTest::Preferences_->PutInt(key, value);
    DBPreferencesFuzzTest::Preferences_->GetInt(key);
    return;
}

void PutStringFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    std::string value = provider.ConsumeRandomLengthString();
    DBPreferencesFuzzTest::Preferences_->PutString(key, value);
    return;
}

void GetStringFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    std::string value = provider.ConsumeRandomLengthString();
    DBPreferencesFuzzTest::Preferences_->PutString(key, value);
    DBPreferencesFuzzTest::Preferences_->GetString(key);
    return;
}

void PutBoolFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeBool();
    DBPreferencesFuzzTest::Preferences_->PutBool(key, value);
    return;
}

void GetBoolFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeBool();
    DBPreferencesFuzzTest::Preferences_->PutBool(key, value);
    DBPreferencesFuzzTest::Preferences_->GetBool(key);
    return;
}

void PutFloatFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<float>();
    DBPreferencesFuzzTest::Preferences_->PutFloat(key, value);
    return;
}

void GetFloatFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<float>();
    DBPreferencesFuzzTest::Preferences_->PutFloat(key, value);
    DBPreferencesFuzzTest::Preferences_->GetFloat(key);
    return;
}

void PutDoubleFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesFuzzTest::Preferences_->PutDouble(key, value);
    return;
}

void GetDoubleFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesFuzzTest::Preferences_->PutDouble(key, value);
    DBPreferencesFuzzTest::Preferences_->GetDouble(key);
    return;
}

void PutLongFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesFuzzTest::Preferences_->PutLong(key, value);
    return;
}

void GetLongFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesFuzzTest::Preferences_->PutLong(key, value);
    DBPreferencesFuzzTest::Preferences_->GetLong(key);
    return;
}

void DeleteFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesFuzzTest::Preferences_->PutLong(key, value);
    DBPreferencesFuzzTest::Preferences_->Delete(key);
    return;
}

void ClearFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesFuzzTest::Preferences_->PutLong(key, value);
    DBPreferencesFuzzTest::Preferences_->Clear();
    return;
}

void FlushFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesFuzzTest::Preferences_->PutLong(key, value);
    DBPreferencesFuzzTest::Preferences_->Flush();
    DBPreferencesFuzzTest::Preferences_->GetLong(key);
    PreferencesHelper::DeletePreferences("/data/test/test");
    return;
}

void FlushSyncFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesFuzzTest::Preferences_->PutLong(key, value);
    DBPreferencesFuzzTest::Preferences_->FlushSync();
    DBPreferencesFuzzTest::Preferences_->GetLong(key);
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
    OHOS::PutVectorFuzz(provider);
    OHOS::GetVectorFuzz(provider);
    OHOS::HasFuzz(provider);
    OHOS::GetValueFuzz(provider);
    OHOS::GetAllFuzz(provider);
    OHOS::GetAllDataFuzz(provider);
    OHOS::GetAllDatasFuzz(provider);
    OHOS::PutIntFuzz(provider);
    OHOS::GetIntFuzz(provider);
    OHOS::PutStringFuzz(provider);
    OHOS::GetStringFuzz(provider);
    OHOS::PutBoolFuzz(provider);
    OHOS::GetBoolFuzz(provider);
    OHOS::PutFloatFuzz(provider);
    OHOS::GetFloatFuzz(provider);
    OHOS::PutDoubleFuzz(provider);
    OHOS::PutLongFuzz(provider);
    OHOS::GetDoubleFuzz(provider);
    OHOS::GetLongFuzz(provider);
    OHOS::DeleteFuzz(provider);
    OHOS::ClearFuzz(provider);
    OHOS::FlushFuzz(provider);
    OHOS::FlushSyncFuzz(provider);
    OHOS::DBPreferencesFuzzTest::TearDownTestCase();
    return 0;
}