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

#include "dbpreferencesget_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_helper.h"

using namespace OHOS::NativePreferences;

namespace OHOS {
class DBPreferencesGetFuzzTest {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::shared_ptr<Preferences> preferences_;
};

std::shared_ptr<Preferences> DBPreferencesGetFuzzTest::preferences_ = nullptr;

void DBPreferencesGetFuzzTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    Options option = {"/data/test/test", "", "", true};
    preferences_ = PreferencesHelper::GetPreferences(option, errCode);
}

void DBPreferencesGetFuzzTest::TearDownTestCase(void)
{
    preferences_->Clear();
    PreferencesHelper::RemovePreferencesFromCache("/data/test/test");
    preferences_ = nullptr;
}

void DBPreferencesGetFuzzTest::SetUp(void)
{
}

void DBPreferencesGetFuzzTest::TearDown(void)
{
}

void HasFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesGetFuzzTest::preferences_->PutInt(key, value);
    DBPreferencesGetFuzzTest::preferences_->HasKey(key);
    return;
}

void GetValueFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesGetFuzzTest::preferences_->PutInt(key, value);
    DBPreferencesGetFuzzTest::preferences_->GetValue(key, 0);
    return;
}

void PutIntFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesGetFuzzTest::preferences_->PutInt(key, value);
    return;
}

void GetIntFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeIntegral<int32_t>();
    DBPreferencesGetFuzzTest::preferences_->PutInt(key, value);
    DBPreferencesGetFuzzTest::preferences_->GetInt(key);
    return;
}

void PutStringFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    std::string value = provider.ConsumeRandomLengthString();
    DBPreferencesGetFuzzTest::preferences_->PutString(key, value);
    return;
}

void GetStringFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    std::string value = provider.ConsumeRandomLengthString();
    DBPreferencesGetFuzzTest::preferences_->PutString(key, value);
    DBPreferencesGetFuzzTest::preferences_->GetString(key);
    return;
}

void PutBoolFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeBool();
    DBPreferencesGetFuzzTest::preferences_->PutBool(key, value);
    return;
}

void GetBoolFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeBool();
    DBPreferencesGetFuzzTest::preferences_->PutBool(key, value);
    DBPreferencesGetFuzzTest::preferences_->GetBool(key);
    return;
}

void PutFloatFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<float>();
    DBPreferencesGetFuzzTest::preferences_->PutFloat(key, value);
    return;
}

void GetFloatFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<float>();
    DBPreferencesGetFuzzTest::preferences_->PutFloat(key, value);
    DBPreferencesGetFuzzTest::preferences_->GetFloat(key);
    return;
}

void PutDoubleFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesGetFuzzTest::preferences_->PutDouble(key, value);
    return;
}

void GetDoubleFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesGetFuzzTest::preferences_->PutDouble(key, value);
    DBPreferencesGetFuzzTest::preferences_->GetDouble(key);
    return;
}

void PutLongFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesGetFuzzTest::preferences_->PutLong(key, value);
    return;
}

void GetLongFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    auto value = provider.ConsumeFloatingPoint<double>();
    DBPreferencesGetFuzzTest::preferences_->PutLong(key, value);
    DBPreferencesGetFuzzTest::preferences_->GetLong(key);
    return;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::DBPreferencesGetFuzzTest::SetUpTestCase();
    OHOS::GetValueFuzz(provider);
    OHOS::GetIntFuzz(provider);
    OHOS::GetStringFuzz(provider);
    OHOS::GetBoolFuzz(provider);
    OHOS::GetFloatFuzz(provider);
    OHOS::GetDoubleFuzz(provider);
    OHOS::GetLongFuzz(provider);
    OHOS::DBPreferencesGetFuzzTest::TearDownTestCase();
    return 0;
}