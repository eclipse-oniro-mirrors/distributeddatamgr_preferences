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
;

void PreferencesFuzzTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    Preferences_ = PreferencesHelper::GetPreferences("/data/test/test", errCode);
}

void PreferencesFuzzTest::TearDownTestCase(void)
{
    Preferences_->Clear();
    PreferencesHelper::RemovePreferencesFromCache("/data/test/test");
}

void PreferencesFuzzTest::SetUp(void)
{
}

void PreferencesFuzzTest::TearDown(void)
{
}

bool PutIntFuzz(FuzzedDataProvider *provider)
{
    std::string skey = provider->ConsumeRandomLengthString();
    auto svalue = provider->ConsumeIntegral<int32_t>(size);
    int ret = PreferencesFuzzTest::Preferences_->PutInt(skey, svalue);
    if (ret != E_OK) {
        return false;
    } else {
        return true;
    }
}

bool GetIntFuzz(FuzzedDataProvider *provider)
{
    std::string skey = provider->ConsumeRandomLengthString();
    auto svalue = provider->ConsumeIntegral<int32_t>();
    PreferencesFuzzTest::Preferences_->PutInt(skey, svalue);
    int ret = PreferencesFuzzTest::Preferences_->GetInt(skey);
    if (ret != svalue) {
        return false;
    } else {
        return true;
    }
}

bool PutStringFuzz(FuzzedDataProvider *provider)
{
    bool result = false;
    std::string skey = provider->ConsumeRandomLengthString();
    std::string svalue = provider->ConsumeRandomLengthString();
    int ret = PreferencesFuzzTest::Preferences_->PutString(skey, svalue);
    if (!ret) {
        result = true;
    }
    return result;
}

bool GetStringFuzz(FuzzedDataProvider *provider)
{
    std::string skey = provider->ConsumeRandomLengthString();
    std::string svalue = provider->ConsumeRandomLengthString();
    PreferencesFuzzTest::Preferences_->PutString(skey, svalue);
    std::string ret = PreferencesFuzzTest::Preferences_->GetString(skey);
    if (ret != svalue) {
        return false;
    } else {
        return true;
    }
}

bool PutBoolFuzz(FuzzedDataProvider *provider)
{
    std::string skey = provider->ConsumeRandomLengthString();
    auto svalue = provider->ConsumeBool();
    int ret = PreferencesFuzzTest::Preferences_->PutBool(skey, svalue);
    if (ret != E_OK) {
        return false;
    } else {
        return true;
    }
}

bool GetBoolFuzz(FuzzedDataProvider *provider)
{
    std::string skey = provider->ConsumeRandomLengthString();
    auto svalue = provider->ConsumeBool();
    PreferencesFuzzTest::Preferences_->PutBool(skey, svalue);
    bool ret = PreferencesFuzzTest::Preferences_->GetBool(skey);
    if (ret != svalue) {
        return false;
    } else {
        return true;
    }
}

bool PutFloatFuzz(FuzzedDataProvider *provider)
{
    std::string skey = provider->ConsumeRandomLengthString();
    auto svalue = provider->ConsumeFloatingPoint();
    int ret = PreferencesFuzzTest::Preferences_->PutFloat(skey, svalue);
    if (ret != E_OK) {
        return false;
    } else {
        return true;
    }
}

bool GetFloatFuzz(FuzzedDataProvider *provider)
{
    std::string skey = provider->ConsumeRandomLengthString();
    auto svalue = provider->ConsumeFloatingPoint();
    PreferencesFuzzTest::Preferences_->PutFloat(skey, svalue);
    bool ret = PreferencesFuzzTest::Preferences_->GetFloat(skey);
    if (ret != svalue) {
        return false;
    } else {
        return true;
    }
}

bool PutDoubleFuzz(FuzzedDataProvider *provider)
{
    std::string skey = provider->ConsumeRandomLengthString();
    auto svalue = provider->ConsumeFloatingPoint();
    int ret = PreferencesFuzzTest::Preferences_->PutDouble(skey, svalue);
    if (ret != E_OK) {
        return false;
    } else {
        return true;
    }
}

bool GetDoubleFuzz(FuzzedDataProvider *provider)
{
    std::string skey = provider->ConsumeRandomLengthString();
    auto svalue = provider->ConsumeFloatingPoint();
    PreferencesFuzzTest::Preferences_->PutDouble(skey, svalue);
    bool ret = PreferencesFuzzTest::Preferences_->GetDouble(skey);
    if (ret != svalue) {
        return false;
    } else {
        return true;
    }
}

bool PutLongFuzz(FuzzedDataProvider *provider)
{
    std::string skey = provider->ConsumeRandomLengthString();
    auto svalue = provider->ConsumeFloatingPoint();
    int ret = PreferencesFuzzTest::Preferences_->PutLong(skey, svalue);
    if (ret != E_OK) {
        return false;
    } else {
        return true;
    }
}

bool GetLongFuzz(FuzzedDataProvider *provider)
{
    std::string skey = provider->ConsumeRandomLengthString();
    auto svalue = provider->ConsumeFloatingPoint();
    PreferencesFuzzTest::Preferences_->PutLong(skey, svalue);
    bool ret = PreferencesFuzzTest::Preferences_->GetLong(skey);
    if (ret != svalue) {
        return false;
    } else {
        return true;
    }
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::PreferencesFuzzTest::SetUpTestCase();
    OHOS::PutIntFuzz(&provider);
    OHOS::GetIntFuzz(&provider);
    OHOS::PutStringFuzz(&provider);
    OHOS::GetStringFuzz(&provider);
    OHOS::PutBoolFuzz(&provider);
    OHOS::GetBoolFuzz(&provider);
    OHOS::PutFloatFuzz(&provider);
    OHOS::GetFloatFuzz(&provider);
    OHOS::PutDoubleFuzz(&provider);
    OHOS::PutLongFuzz(&provider);
    OHOS::PutDoubleFuzz(&provider);
    OHOS::GetLongFuzz(&provider);
    OHOS::PreferencesFuzzTest::TearDownTestCase();
    return 0;
}