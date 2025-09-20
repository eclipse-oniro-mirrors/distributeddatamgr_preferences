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

#include "dbpreferencesvector_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_helper.h"

using namespace OHOS::NativePreferences;

namespace OHOS {
constexpr size_t NUM_MIN = 1;
constexpr size_t NUM_MAX = 32 * 1024 * 1024;
class DBPreferencesVectorFuzzTest {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::shared_ptr<Preferences> preferences_;
};

std::shared_ptr<Preferences> DBPreferencesVectorFuzzTest::preferences_ = nullptr;

void DBPreferencesVectorFuzzTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    Options option = {"/data/test/test", "", "", true};
    preferences_ = PreferencesHelper::GetPreferences(option, errCode);
}

void DBPreferencesVectorFuzzTest::TearDownTestCase(void)
{
    preferences_->Clear();
    PreferencesHelper::RemovePreferencesFromCache("/data/test/test");
    preferences_ = nullptr;
}

void DBPreferencesVectorFuzzTest::SetUp(void)
{
}

void DBPreferencesVectorFuzzTest::TearDown(void)
{
}

void PutVectorFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(NUM_MIN, NUM_MAX);
    std::vector<uint8_t> value = provider.ConsumeBytes<uint8_t>(bytesSize);
    DBPreferencesVectorFuzzTest::preferences_->Put(key, value);
    return;
}

void GetVectorFuzz(FuzzedDataProvider &provider)
{
    std::string key = provider.ConsumeRandomLengthString();
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(NUM_MIN, NUM_MAX);
    std::vector<uint8_t> value = provider.ConsumeBytes<uint8_t>(bytesSize);
    DBPreferencesVectorFuzzTest::preferences_->Put(key, value);
    DBPreferencesVectorFuzzTest::preferences_->Get(key, 0);
    return;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::DBPreferencesVectorFuzzTest::SetUpTestCase();
    OHOS::PutVectorFuzz(provider);
    OHOS::GetVectorFuzz(provider);
    OHOS::DBPreferencesVectorFuzzTest::TearDownTestCase();
    return 0;
}