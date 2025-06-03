/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <cctype>
#include <condition_variable>
#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <functional>
#include <gtest/gtest.h>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <thread>
#include <vector>

#include "log_print.h"
#include "preferences_test_utils.h"
#include "oh_preferences_impl.h"
#include "oh_preferences.h"
#include "oh_preferences_err_code.h"
#include "oh_preferences_value.h"
#include "oh_preferences_option.h"
#include "preferences_helper.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::PreferencesNdk;
using namespace OHOS::NativePreferences;
namespace {

const std::string TEST_PATH = "/data/test/";

class PreferencesNdkStorageTypeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PreferencesNdkStorageTypeTest::SetUpTestCase(void)
{
    NdkTestUtils::CreateDirectoryRecursively(TEST_PATH);
}
void PreferencesNdkStorageTypeTest::TearDownTestCase(void) {}

void PreferencesNdkStorageTypeTest::SetUp(void)
{
    NdkTestUtils::CreateDirectoryRecursively(TEST_PATH);
}

void PreferencesNdkStorageTypeTest::TearDown(void) {}

static bool IsFileExist(const std::string &path)
{
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

/**
 * @tc.name: NDKStorageTypeBaseTest_001
 * @tc.desc: test api OH_Preferences_IsStorageTypeSupported
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesNdkStorageTypeTest, NDKStorageTypeBaseTest_001, TestSize.Level0)
{
    bool isSupport = false;
    int errCode = OH_Preferences_IsStorageTypeSupported(Preferences_StorageType::PREFERENCES_STORAGE_XML, &isSupport);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    ASSERT_EQ(isSupport, true);

    errCode = OH_Preferences_IsStorageTypeSupported(Preferences_StorageType::PREFERENCES_STORAGE_GSKV, &isSupport);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    ASSERT_EQ(isSupport, false);

    errCode = OH_Preferences_IsStorageTypeSupported(
        static_cast<Preferences_StorageType>(Preferences_StorageType::PREFERENCES_STORAGE_XML - 1), &isSupport);
    ASSERT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    errCode = OH_Preferences_IsStorageTypeSupported(
        static_cast<Preferences_StorageType>(Preferences_StorageType::PREFERENCES_STORAGE_GSKV + 1), &isSupport);
    ASSERT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);
}

/**
 * @tc.name: NDKStorageTypeBaseTest_002
 * @tc.desc: test storage type when default which is not setting storage type
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesNdkStorageTypeTest, NDKStorageTypeBaseTest_002, TestSize.Level0)
{
    // without setting storage type
    // it should be xml when not in enhance by default, or GSKV in enhance
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    const char *fileName = "CStorageTypeTest002";
    ASSERT_EQ(OH_PreferencesOption_SetFileName(option, fileName), PREFERENCES_OK);
    int errCode = PREFERENCES_OK;
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(OH_Preferences_SetInt(pref, "key", 2), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);

    bool isEnhance = false;
    errCode = OH_Preferences_IsStorageTypeSupported(Preferences_StorageType::PREFERENCES_STORAGE_GSKV, &isEnhance);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    if (isEnhance) {
        ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName) + ".db"), true);
        ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName)), false);
    } else {
        ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName) + ".db"), false);
        ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName)), true);
    }
    ASSERT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences(TEST_PATH + std::string(fileName)),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKStorageTypeXMLTest_003
 * @tc.desc: test storage type when new with xml, and open with xml when xml exists
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesNdkStorageTypeTest, NDKStorageTypeXMLTest_003, TestSize.Level0)
{
    // new with xml storage type
    // it should be xml in enhance or not
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    const char *fileName = "CStorageTypeTest003";
    ASSERT_EQ(OH_PreferencesOption_SetFileName(option, fileName), PREFERENCES_OK);
    bool isXmlSupported = false;
    ASSERT_EQ(OH_Preferences_IsStorageTypeSupported(Preferences_StorageType::PREFERENCES_STORAGE_XML, &isXmlSupported),
        PREFERENCES_OK);
    ASSERT_EQ(isXmlSupported, true);
    ASSERT_EQ(OH_PreferencesOption_SetStorageType(option, Preferences_StorageType::PREFERENCES_STORAGE_XML),
        PREFERENCES_OK);
    int errCode = PREFERENCES_OK;
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    ASSERT_EQ(OH_Preferences_SetInt(pref, "key", 2), PREFERENCES_OK);
    ASSERT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName) + ".db"), false);
    ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName)), true);

    // xml exists, open in xml mode
    pref = OH_Preferences_Open(option, &errCode);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    ASSERT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    (void)OH_PreferencesOption_Destroy(option);

    ASSERT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences(TEST_PATH + std::string(fileName)),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKStorageTypeXMLTest_003
 * @tc.desc: test storage type when GSKV exists and open with xml
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesNdkStorageTypeTest, NDKStorageTypeXMLTest_004, TestSize.Level0)
{
    // GSKV exists, open in xml mode, should return invalid_args
    // create fake GSKV firstly
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    const char *fileName = "CStorageTypeTest004";
    ASSERT_EQ(OH_PreferencesOption_SetFileName(option, "CStorageTypeTest004.db"), PREFERENCES_OK);
    ASSERT_EQ(OH_PreferencesOption_SetStorageType(option, Preferences_StorageType::PREFERENCES_STORAGE_XML),
        PREFERENCES_OK);
    int errCode = PREFERENCES_OK;
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    ASSERT_EQ(OH_Preferences_SetInt(pref, "key", 2), PREFERENCES_OK);
    ASSERT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName) + ".db"), true);
    ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName)), false);


    // open in xml mode
    ASSERT_EQ(OH_PreferencesOption_SetFileName(option, fileName), PREFERENCES_OK);
    pref = OH_Preferences_Open(option, &errCode);
    ASSERT_EQ(errCode, PREFERENCES_ERROR_NOT_SUPPORTED);

    (void)OH_PreferencesOption_Destroy(option);
}

/**
 * @tc.name: NDKStorageTypeGSKVTest_005
 * @tc.desc: test storage type when new with GSKV
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesNdkStorageTypeTest, NDKStorageTypeGSKVTest_005, TestSize.Level0)
{
    // new with GSKV mode
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    const char *fileName = "CStorageTypeTest005";
    ASSERT_EQ(OH_PreferencesOption_SetFileName(option, fileName), PREFERENCES_OK);

    bool isEnhance = false;
    int errCode = OH_Preferences_IsStorageTypeSupported(Preferences_StorageType::PREFERENCES_STORAGE_GSKV, &isEnhance);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    if (isEnhance) {
        ASSERT_EQ(OH_PreferencesOption_SetStorageType(option, Preferences_StorageType::PREFERENCES_STORAGE_GSKV),
            PREFERENCES_OK);
        OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
        ASSERT_EQ(errCode, PREFERENCES_OK);
        ASSERT_EQ(OH_Preferences_SetInt(pref, "key", 2), PREFERENCES_OK);
        ASSERT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
        ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName) + ".db"), true);
        ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName)), false);
    } else {
        ASSERT_EQ(OH_PreferencesOption_SetStorageType(option, Preferences_StorageType::PREFERENCES_STORAGE_GSKV),
            PREFERENCES_OK);
        (void)OH_Preferences_Open(option, &errCode);
        ASSERT_EQ(errCode, PREFERENCES_ERROR_NOT_SUPPORTED);
        ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName) + ".db"), false);
        ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName)), false);
    }
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences(TEST_PATH + std::string(fileName)),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKStorageTypeGSKVTest_006
 * @tc.desc: test storage type when xml exists but open with GSKV
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesNdkStorageTypeTest, NDKStorageTypeGSKVTest_006, TestSize.Level0)
{
    // xml exists but open with GSKV
    // create xml firstly
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    const char *fileName = "CStorageTypeTest006";
    ASSERT_EQ(OH_PreferencesOption_SetFileName(option, fileName), PREFERENCES_OK);
    ASSERT_EQ(OH_PreferencesOption_SetStorageType(option, Preferences_StorageType::PREFERENCES_STORAGE_XML),
        PREFERENCES_OK);
    int errCode = PREFERENCES_OK;
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    ASSERT_EQ(OH_Preferences_SetInt(pref, "key", 2), PREFERENCES_OK);
    ASSERT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName) + ".db"), false);
    ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName)), true);

    // open with GSKV
    bool isEnhance = false;
    errCode = OH_Preferences_IsStorageTypeSupported(Preferences_StorageType::PREFERENCES_STORAGE_GSKV, &isEnhance);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    if (isEnhance) {
        ASSERT_EQ(OH_PreferencesOption_SetStorageType(option, Preferences_StorageType::PREFERENCES_STORAGE_GSKV),
            PREFERENCES_OK);
        pref = OH_Preferences_Open(option, &errCode);
        ASSERT_EQ(errCode, PREFERENCES_ERROR_NOT_SUPPORTED);
    } else {
        ASSERT_EQ(OH_PreferencesOption_SetStorageType(option, Preferences_StorageType::PREFERENCES_STORAGE_GSKV),
            PREFERENCES_OK);
        pref = OH_Preferences_Open(option, &errCode);
        ASSERT_EQ(errCode, PREFERENCES_ERROR_NOT_SUPPORTED);
    }

    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences(TEST_PATH + std::string(fileName)),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKStorageTypeGSKVTest_007
 * @tc.desc: test storage type when GSKV exists but open with GSKV
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesNdkStorageTypeTest, NDKStorageTypeGSKVTest_007, TestSize.Level0)
{
    // GSKV exists, open in GSKV mode
    bool isEnhance = false;
    int errCode = OH_Preferences_IsStorageTypeSupported(Preferences_StorageType::PREFERENCES_STORAGE_GSKV, &isEnhance);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    if (isEnhance) {
        // create GSKV firstly
        const char *fileName = "CStorageTypeTest007";
        ASSERT_EQ(OH_PreferencesOption_SetFileName(option, fileName), PREFERENCES_OK);
        ASSERT_EQ(OH_PreferencesOption_SetStorageType(option, Preferences_StorageType::PREFERENCES_STORAGE_GSKV),
            PREFERENCES_OK);
        OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
        ASSERT_EQ(errCode, PREFERENCES_OK);
        ASSERT_EQ(OH_Preferences_SetInt(pref, "key", 2), PREFERENCES_OK);
        ASSERT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
        ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName) + ".db"), true);
        ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName)), false);

        // open again
        pref = OH_Preferences_Open(option, &errCode);
        ASSERT_EQ(errCode, PREFERENCES_OK);
        ASSERT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    } else {
        // create fake GSKV firstly
        const char *fileName = "CStorageTypeTest007Fake.db";
        ASSERT_EQ(OH_PreferencesOption_SetFileName(option, fileName), PREFERENCES_OK);
        // xml by default when not enhance
        OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
        ASSERT_EQ(errCode, PREFERENCES_OK);
        ASSERT_EQ(OH_Preferences_SetInt(pref, "key", 2), PREFERENCES_OK);
        ASSERT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
        ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName) + ".db"), false);
        ASSERT_EQ(IsFileExist(TEST_PATH + std::string(fileName)), true);

        // open again
        ASSERT_EQ(OH_PreferencesOption_SetStorageType(option, Preferences_StorageType::PREFERENCES_STORAGE_GSKV),
            PREFERENCES_OK);
        pref = OH_Preferences_Open(option, &errCode);
        ASSERT_EQ(errCode, PREFERENCES_ERROR_NOT_SUPPORTED);
    }
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences(TEST_PATH + "CStorageTypeTest007"),
        OHOS::NativePreferences::E_OK);
    ASSERT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences(TEST_PATH + "CStorageTypeTest007Fake.db"),
        OHOS::NativePreferences::E_OK);
}
} // namespace
