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
}

void PreferencesFuzzTest::SetUp(void)
{
}

void PreferencesFuzzTest::TearDown(void)
{
}

bool PutIntFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    auto svalue = static_cast<int>(size);
    int ret = PreferencesFuzzTest::Preferences_->PutInt(skey, svalue);
    if (ret != E_OK) {
        return false;
    } else {
        return true;
    }
}

bool GetIntFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    auto svalue = static_cast<int>(size);
    PreferencesFuzzTest::Preferences_->PutInt(skey, svalue);
    int ret = PreferencesFuzzTest::Preferences_->GetInt(skey);
    if (ret != svalue) {
        return false;
    } else {
        return true;
    }
}

bool PutStringFuzz(const uint8_t *data, size_t size)
{
    bool result = false;
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    int ret = PreferencesFuzzTest::Preferences_->PutString(skey, svalue);
    if (!ret) {
        result = true;
    }
    return result;
}

bool GetStringFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    std::string svalue(data, data + size);
    PreferencesFuzzTest::Preferences_->PutString(skey, svalue);
    std::string ret = PreferencesFuzzTest::Preferences_->GetString(skey);
    if (ret != svalue) {
        return false;
    } else {
        return true;
    }
}

bool PutBoolFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    auto svalue = ((size % 2) == 0);
    int ret = PreferencesFuzzTest::Preferences_->PutBool(skey, svalue);
    if (ret != E_OK) {
        return false;
    } else {
        return true;
    }
}

bool GetBoolFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    auto svalue = ((size % 2) == 0);
    PreferencesFuzzTest::Preferences_->PutBool(skey, svalue);
    bool ret = PreferencesFuzzTest::Preferences_->GetBool(skey);
    if (ret != svalue) {
        return false;
    } else {
        return true;
    }
}

bool PutFloatFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    auto svalue = static_cast<float>(size);
    int ret = PreferencesFuzzTest::Preferences_->PutFloat(skey, svalue);
    if (ret != E_OK) {
        return false;
    } else {
        return true;
    }
}

bool GetFloatFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    auto svalue = static_cast<float>(size);
    PreferencesFuzzTest::Preferences_->PutFloat(skey, svalue);
    bool ret = PreferencesFuzzTest::Preferences_->GetFloat(skey);
    if (ret != svalue) {
        return false;
    } else {
        return true;
    }
}

bool PutDoubleFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    auto svalue = static_cast<double>(size);
    int ret = PreferencesFuzzTest::Preferences_->PutDouble(skey, svalue);
    if (ret != E_OK) {
        return false;
    } else {
        return true;
    }
}

bool GetDoubleFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    auto svalue = static_cast<double>(size);
    PreferencesFuzzTest::Preferences_->PutDouble(skey, svalue);
    bool ret = PreferencesFuzzTest::Preferences_->GetDouble(skey);
    if (ret != svalue) {
        return false;
    } else {
        return true;
    }
}

bool PutLongFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    auto svalue = static_cast<double>(size);
    int ret = PreferencesFuzzTest::Preferences_->PutLong(skey, svalue);
    if (ret != E_OK) {
        return false;
    } else {
        return true;
    }
}

bool GetLongFuzz(const uint8_t *data, size_t size)
{
    std::string skey(data, data + size);
    auto svalue = static_cast<double>(size);
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
    OHOS::PreferencesFuzzTest::SetUpTestCase();
    OHOS::PutIntFuzz(data, size);
    OHOS::GetIntFuzz(data, size);
    OHOS::PutStringFuzz(data, size);
    OHOS::GetStringFuzz(data, size);
    OHOS::PutBoolFuzz(data, size);
    OHOS::GetBoolFuzz(data, size);
    OHOS::PutFloatFuzz(data, size);
    OHOS::GetFloatFuzz(data, size);
    OHOS::PutDoubleFuzz(data, size);
    OHOS::PutLongFuzz(data, size);
    OHOS::PutDoubleFuzz(data, size);
    OHOS::GetLongFuzz(data, size);
    return 0;
}