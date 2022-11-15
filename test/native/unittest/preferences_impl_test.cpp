/*
* Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "preferences_impl.h"

#include <gtest/gtest.h>

#include <cctype>
#include <iostream>
#include <string>

#include "logger.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_observer.h"

using namespace testing::ext;
using namespace OHOS::NativePreferences;

class PreferencesImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PreferencesImplTest::SetUpTestCase(void)
{
}

void PreferencesImplTest::TearDownTestCase(void)
{
}

void PreferencesImplTest::SetUp(void)
{
}

void PreferencesImplTest::TearDown(void)
{
}

/**
* @tc.name: NativePreferencesImplTest_001
* @tc.desc: normal testcase of DeletePreferences
* @tc.type: FUNC
* @tc.require: SR000CU2BL
* @tc.author: xiuhongju
*/
HWTEST_F(PreferencesImplTest, NativePreferencesHelperTest_001, TestSize.Level1)
{
//    int errCode = E_OK;
//    string path = "/data/test/test_helper";
//    static const int maxPathLength = 4096;
//    for (int i = 0; i < maxPathLength; ++i) {
//        path.append(std::to_string(i));
//    }
}

