/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "preferences_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_helper.h"

using namespace OHOS::NativePreferences;

namespace OHOS {
class PreferencesFuzzTest {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::shared_ptr<Preferences> Preferences_;

    static const std::string LONG_KEY;
};

std::shared_ptr<Preferences> PreferencesFuzzTest::Preferences_ = nullptr;

const std::string PreferencesFuzzTest::LONG_KEY = std::string(Preferences::MAX_KEY_LENGTH, std::toupper('a'));

void PreferencesFuzzTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    Preferences_ = PreferencesHelper::GetPreferences("/data/test/test", errCode);
}

void PreferencesFuzzTest::TearDownTestCase(void)
{
    Preferences_->Clear();
    PreferencesHelper::RemovePreferencesFromCache("/data/test/test");
    Preferences_ = nullptr;
}

void PreferencesFuzzTest::SetUp(void)
{
}

void PreferencesFuzzTest::TearDown(void)
{
}

bool PutFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeIntegral<int32_t>();
    int ret = PreferencesFuzzTest::Preferences_->Put(skey, svalue);
    return ret == E_OK;
}

bool HasFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeIntegral<int32_t>();
    PreferencesFuzzTest::Preferences_->PutInt(skey, svalue);
    bool has = PreferencesFuzzTest::Preferences_->HasKey(skey);
    return has;
}

bool GetFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeIntegral<int32_t>();
    PreferencesFuzzTest::Preferences_->PutInt(skey, svalue);
    auto ret = PreferencesFuzzTest::Preferences_->Get(skey, 0);
    return (int32_t)ret == svalue;
}

bool GetValueFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeIntegral<int32_t>();
    PreferencesFuzzTest::Preferences_->PutInt(skey, svalue);
    auto ret = PreferencesFuzzTest::Preferences_->GetValue(skey, 0);
    return ret.first == E_OK;
}

bool GetAllFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeIntegral<int32_t>();
    PreferencesFuzzTest::Preferences_->PutInt(skey, svalue);
    auto ret = PreferencesFuzzTest::Preferences_->GetAll();
    return ret.empty();
}

bool GetAllDataFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeIntegral<int32_t>();
    PreferencesFuzzTest::Preferences_->PutInt(skey, svalue);
    auto ret = PreferencesFuzzTest::Preferences_->GetAllData();
    return ret.first == E_OK;
}

bool GetAllDatasFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeIntegral<int32_t>();
    PreferencesFuzzTest::Preferences_->PutInt(skey, svalue);
    auto ret = PreferencesFuzzTest::Preferences_->GetAllDatas();
    return ret.empty();
}

bool PutIntFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeIntegral<int32_t>();
    int ret = PreferencesFuzzTest::Preferences_->PutInt(skey, svalue);
    return ret == E_OK;
}

bool GetIntFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeIntegral<int32_t>();
    PreferencesFuzzTest::Preferences_->PutInt(skey, svalue);
    int ret = PreferencesFuzzTest::Preferences_->GetInt(skey);
    return ret == svalue;
}

bool PutStringFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    std::string svalue = provider.ConsumeRandomLengthString();
    int ret = PreferencesFuzzTest::Preferences_->PutString(skey, svalue);
    return ret == E_OK;
}

bool GetStringFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    std::string svalue = provider.ConsumeRandomLengthString();
    PreferencesFuzzTest::Preferences_->PutString(skey, svalue);
    std::string ret = PreferencesFuzzTest::Preferences_->GetString(skey);
    return ret == svalue;
}

bool PutBoolFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeBool();
    int ret = PreferencesFuzzTest::Preferences_->PutBool(skey, svalue);
    return ret == E_OK;
}

bool GetBoolFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeBool();
    PreferencesFuzzTest::Preferences_->PutBool(skey, svalue);
    bool ret = PreferencesFuzzTest::Preferences_->GetBool(skey);
    return ret == svalue;
}

bool PutFloatFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeFloatingPoint<float>();
    int ret = PreferencesFuzzTest::Preferences_->PutFloat(skey, svalue);
    return ret == E_OK;
}

bool GetFloatFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeFloatingPoint<float>();
    PreferencesFuzzTest::Preferences_->PutFloat(skey, svalue);
    float ret = PreferencesFuzzTest::Preferences_->GetFloat(skey);
    return ret == svalue;
}

bool PutDoubleFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeFloatingPoint<double>();
    int ret = PreferencesFuzzTest::Preferences_->PutDouble(skey, svalue);
    return ret == E_OK;
}

bool GetDoubleFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeFloatingPoint<double>();
    PreferencesFuzzTest::Preferences_->PutDouble(skey, svalue);
    double ret = PreferencesFuzzTest::Preferences_->GetDouble(skey);
    return ret == svalue;
}

bool PutLongFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeFloatingPoint<double>();
    int ret = PreferencesFuzzTest::Preferences_->PutLong(skey, svalue);
    return ret == E_OK;
}

bool GetLongFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeFloatingPoint<double>();
    PreferencesFuzzTest::Preferences_->PutLong(skey, svalue);
    int64_t ret = PreferencesFuzzTest::Preferences_->GetLong(skey);
    return ret == svalue;
}

bool DeleteFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeFloatingPoint<double>();
    PreferencesFuzzTest::Preferences_->PutLong(skey, svalue);
    int64_t ret = PreferencesFuzzTest::Preferences_->Delete(skey);
    return ret == NativePreferences::E_OK;
}

bool ClearFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeFloatingPoint<double>();
    PreferencesFuzzTest::Preferences_->PutLong(skey, svalue);
    int64_t ret = PreferencesFuzzTest::Preferences_->Clear();
    return ret == NativePreferences::E_OK;;
}

bool FlushFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeFloatingPoint<double>();
    PreferencesFuzzTest::Preferences_->PutLong(skey, svalue);
    PreferencesFuzzTest::Preferences_->Flush();
    int64_t ret = PreferencesFuzzTest::Preferences_->GetLong(skey);
    PreferencesHelper::DeletePreferences("/data/test/test");
    return ret == NativePreferences::E_OK;;
}

bool FlushSyncFuzz(FuzzedDataProvider &provider)
{
    std::string skey = provider.ConsumeRandomLengthString();
    auto svalue = provider.ConsumeFloatingPoint<double>();
    PreferencesFuzzTest::Preferences_->PutLong(skey, svalue);
    PreferencesFuzzTest::Preferences_->FlushSync();
    int64_t ret = PreferencesFuzzTest::Preferences_->GetLong(skey);
    PreferencesHelper::DeletePreferences("/data/test/test");
    return ret == NativePreferences::E_OK;;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::PreferencesFuzzTest::SetUpTestCase();
    OHOS::PutFuzz(provider);
    OHOS::HasFuzz(provider);
    OHOS::GetFuzz(provider);
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
    OHOS::PreferencesFuzzTest::TearDownTestCase();
    return 0;
}