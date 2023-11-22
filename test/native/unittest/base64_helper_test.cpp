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

#include "base64_helper.h"

#include <gtest/gtest.h>

#include <string>

#include "log_print.h"

using namespace testing::ext;
using namespace OHOS::NativePreferences;
namespace {
class Base64HelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void Base64HelperTest::SetUpTestCase(void)
{
}

void Base64HelperTest::TearDownTestCase(void)
{
}

void Base64HelperTest::SetUp(void)
{
}

void Base64HelperTest::TearDown(void)
{
}

/**
 * @tc.name: Base64HelperTest_0001
 * @tc.desc: normal testcase of base64 encode
 * @tc.type: FUNC
 * @tc.require: SR000CU2BL
 * @tc.author: xiuhongju
 */
HWTEST_F(Base64HelperTest, Base64HelperTest_001, TestSize.Level1)
{
    std::vector<uint8_t> emptyArray {};
    std::vector<uint8_t> oneArray { 'a' };
    std::vector<uint8_t> twoArray { 'a', 'b' };
    std::vector<uint8_t> threeArray { 'a', 'b', 'c' };
    auto result = Base64Helper::Encode(emptyArray);
    EXPECT_EQ(result, "");

    result = Base64Helper::Encode(oneArray);
    EXPECT_EQ(result.length(), 4);
    EXPECT_EQ(result, "YQ==");

    result = Base64Helper::Encode(twoArray);
    EXPECT_EQ(result.length(), 4);
    EXPECT_EQ(result, "YWI=");

    result = Base64Helper::Encode(threeArray);
    EXPECT_EQ(result.length(), 4);
    EXPECT_EQ(result, "YWJj");
}

/**
 * @tc.name: Base64HelperTest_002
 * @tc.desc: normal testcase of base64 decode
 * @tc.type: FUNC
 */
HWTEST_F(Base64HelperTest, Base64HelperTest_002, TestSize.Level1)
{
    std::vector<uint8_t> oneArray { 1 };
    std::vector<uint8_t> twoArray { 1, 2 };
    std::vector<uint8_t> threeArray { 1, 2, 3 };
    std::vector<uint8_t> result {};

    EXPECT_TRUE(Base64Helper::Decode(Base64Helper::Encode(oneArray), result));
    EXPECT_EQ(result, oneArray);

    EXPECT_TRUE(Base64Helper::Decode(Base64Helper::Encode(twoArray), result));
    EXPECT_EQ(result, twoArray);

    EXPECT_TRUE(Base64Helper::Decode(Base64Helper::Encode(threeArray), result));
    EXPECT_EQ(result, threeArray);
}

/**
 * @tc.name: Base64HelperTest_003
 * @tc.desc: error testcase of base64 decode
 * @tc.type: FUNC
 */
HWTEST_F(Base64HelperTest, Base64HelperTest_003, TestSize.Level1)
{
    std::string wrongText = "abc";
    std::vector<uint8_t> result {};
    EXPECT_FALSE(Base64Helper::Decode(wrongText, result));

    wrongText = "@bcd";
    EXPECT_FALSE(Base64Helper::Decode(wrongText, result));

    wrongText = "a@cd";
    EXPECT_FALSE(Base64Helper::Decode(wrongText, result));

    wrongText = "ab@d";
    EXPECT_FALSE(Base64Helper::Decode(wrongText, result));

    wrongText = "abc@";
    EXPECT_FALSE(Base64Helper::Decode(wrongText, result));
}

/**
 * @tc.name: Base64HelperTest_004
 * @tc.desc: error testcase of base64 decode
 * @tc.type: FUNC
 */
HWTEST_F(Base64HelperTest, Base64HelperTest_004, TestSize.Level1)
{
    std::vector<uint8_t> array;
    for (size_t i = 0; i < 256; ++i) {
        array.push_back(i);
    }
    std::string encodeStr = Base64Helper::Encode(array);
    std::vector<uint8_t> decodeArray;
    EXPECT_TRUE(Base64Helper::Decode(encodeStr, decodeArray));
    EXPECT_TRUE(array == decodeArray);
}
}
