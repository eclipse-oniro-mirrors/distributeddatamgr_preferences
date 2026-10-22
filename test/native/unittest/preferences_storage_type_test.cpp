/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "log_print.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_file_operation.h"
#include "preferences_helper.h"
#include "preferences_observer.h"
#include "preferences_value.h"

using namespace testing::ext;
using namespace OHOS::NativePreferences;

namespace {

static void CreateDirectoryRecursively(const std::string &path)
{
    std::string::size_type pos = path.find_last_of('/');
    if (pos == std::string::npos || path.front() != '/') {
        printf("path can not be relative path.\n");
    }
    std::string dir = path.substr(0, pos);

    std::string tempDirectory = dir;
    std::vector<std::string> directories;

    pos = tempDirectory.find('/');
    while (pos != std::string::npos) {
        std::string directory = tempDirectory.substr(0, pos);
        if (!directory.empty()) {
            directories.push_back(directory);
        }
        tempDirectory = tempDirectory.substr(pos + 1);
        pos = tempDirectory.find('/');
    }
    directories.push_back(tempDirectory);

    std::string databaseDirectory;
    for (const std::string& directory : directories) {
        databaseDirectory = databaseDirectory + "/" + directory;
        if (OHOS::NativePreferences::Access(databaseDirectory.c_str()) != F_OK) {
            if (OHOS::NativePreferences::Mkdir(databaseDirectory)) {
                printf("failed to mkdir, errno %d, %s \n", errno, databaseDirectory.c_str());
                return;
            }
        }
    }
}

static bool IsFileExist(const std::string &path)
{
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

class PreferencesStorageTypeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PreferencesStorageTypeTest::SetUpTestCase(void)
{
    CreateDirectoryRecursively("/data/test/");
}

void PreferencesStorageTypeTest::TearDownTestCase(void)
{
}

void PreferencesStorageTypeTest::SetUp(void)
{
    CreateDirectoryRecursively("/data/test/");
}

void PreferencesStorageTypeTest::TearDown(void)
{
}

/**
 * @tc.name: StorageTypeBaseTest000
 * @tc.desc: test IsStorageTypeSupported api
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeBaseTest000, TestSize.Level0)
{
    ASSERT_EQ(PreferencesHelper::IsStorageTypeSupported(StorageType::XML), true);
    ASSERT_EQ(PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV), false);
}

/**
 * @tc.name: StorageTypeBaseTest002
 * @tc.desc: base test, use different storage type to get preferences and check file type
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeBaseTest002, TestSize.Level0)
{
    printf("test with xml\n");
    // default option constructor
    int errCode = E_OK;
    std::string filePath = "/data/test/XML002_1";
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(filePath, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    ASSERT_EQ(IsFileExist(filePath + ".db"), false);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);

    filePath = "/data/test/XML002_2";
    Options option = Options(filePath, "", "", false);
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    ASSERT_EQ(IsFileExist(filePath + ".db"), false);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);

    filePath = "/data/test/GSKV002";
    Options option2 = Options(filePath, "", "", true);
    pref = PreferencesHelper::GetPreferences(option2, errCode);
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        printf("test with GSKV\n");
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(IsFileExist(filePath), false);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
    } else {
        ASSERT_EQ(errCode, E_NOT_SUPPORTED);
    }
}

/**
 * @tc.name: StorageTypeBaseTest004
 * @tc.desc: base test, test get again with different mode
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeBaseTest004, TestSize.Level0)
{
    printf("test with xml\n");
    // xml exist and open with GSKV mode
    int errCode = E_OK;
    std::string filePath = "/data/test/XML004";
    Options option = Options(filePath, "", "", false);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    option.isEnhance = true;
    // in cache, not check type, just return
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    // not in cahce, invalid storage type
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_NOT_SUPPORTED);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);

    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        printf("test with GSKV\n");
        // GSKV exist and open with xml mode
        filePath = "/data/test/GSKV004";
        option.filePath = filePath;
        option.isEnhance = true;
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(IsFileExist(filePath), false);
        option.isEnhance = false;
        // in cache, not check type, just return
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        // not in cahce, invalid storage type
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_NOT_SUPPORTED);
        ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
    }
}

/**
 * @tc.name: StorageTypeCombineTest005
 * @tc.desc: combine test, test xml mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest005, TestSize.Level0)
{
    // new with xml mode in white list
    printf("test with xml\n");
    int errCode = E_OK;
    std::string filePath = "/data/test/White005";
    Options option = Options(filePath, "abcuttestabc", ""); // XML type
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(errCode, E_OK);
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        printf("test with GSKV\n");
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(IsFileExist(filePath), false);
    } else {
        ASSERT_EQ(IsFileExist(filePath), true);
        ASSERT_EQ(IsFileExist(filePath + ".db"), false);
    }
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);

    // not white
    filePath = "/data/test/Normal005";
    option.filePath = filePath;
    option.bundleName = "abcabc";
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    ASSERT_EQ(IsFileExist(filePath + ".db"), false);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: StorageTypeCombineTest006
 * @tc.desc: combine test, test xml mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest006, TestSize.Level0)
{
    // new with xml exists in xml mode
    // create xml firstly
    int errCode = E_OK;
    std::string filePath = "/data/test/XML006";
    Options option = Options(filePath, "", "");
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);

    // in white list, when xml exist, open with xml mode, it should be xml even in enhance
    option.isEnhance = false;
    option.bundleName = "abcuttestabc";
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        printf("test with GSKV\n");
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath), true);
    }

    // not in white list, open with xml mode when xml exists
    Options option2 = Options(filePath, "abc", "", false);
    pref = PreferencesHelper::GetPreferences(option2, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    ASSERT_EQ(IsFileExist(filePath + ".db"), false);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: StorageTypeCombineTest007
 * @tc.desc: combine test, test xml mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest007, TestSize.Level0)
{
    // create fake GSKV firstly
    int errCode = E_OK;
    std::string filePath = "/data/test/XML007";
    Options option = Options(filePath + ".db", "", "");
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(IsFileExist(filePath + ".db"), true);
    ASSERT_EQ(IsFileExist(filePath), false);
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        // open with white list in xml mode
        // it should be xml
        Options option1 = Options(filePath, "abcuttestabc", "", false);
        pref = PreferencesHelper::GetPreferences(option1, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(pref->PutString("key", "value"), E_OK);
        ASSERT_EQ(pref->FlushSync(), E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath), true);
    }

    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath + ".db"), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);

    if (isEnhance) {
        // create GSKV firstly
        printf("test with GSKV\n");
        filePath = "/data/test/GSKV007";
        option.filePath = filePath;
        option.isEnhance = true;
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

        // open in xml mode with white list, it should be GSKV
        option.bundleName = "abcuttestabc";
        option.isEnhance = false;
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath), false);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
    }
}

/**
 * @tc.name: StorageTypeCombineTest008
 * @tc.desc: combine test, test xml mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest008, TestSize.Level0)
{
    // create fake GSKV firstly
    int errCode = E_OK;
    printf("test with xml\n");
    std::string filePath = "/data/test/XML008";
    Options option1 = Options(filePath + ".db", "", "");
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option1, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(IsFileExist(filePath + ".db"), true);
    ASSERT_EQ(IsFileExist(filePath), false);

    // open with xml mode, not in white list
    // GSKV exists, should return E_NOT_SUPPORTED
    Options option = Options(filePath, "abc", "", false);
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_NOT_SUPPORTED);
    ASSERT_EQ(IsFileExist(filePath), false);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath + ".db"), E_OK);

    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        // same case in enhance
        printf("test with GSKV\n");
        filePath = "/data/test/GSKV008";
        option.filePath = filePath;
        option.isEnhance = true;
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

        option.isEnhance = false;
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_NOT_SUPPORTED);
        ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
    }
}

/**
 * @tc.name: StorageTypeCombineTest009
 * @tc.desc: combine test, test GSKV mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest009, TestSize.Level0)
{
    // new with GSKV mode
    // white list
    int errCode = E_OK;
    std::string filePath = "/data/test/White009";
    Options option = Options(filePath, "abcuttestabc", "", true);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        printf("test with GSKV\n");
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(IsFileExist(filePath), false);
    } else {
        ASSERT_EQ(IsFileExist(filePath + ".db"), false);
        ASSERT_EQ(IsFileExist(filePath), true);
    }
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);

    // new with GSKV mode and not in white list
    filePath = "/data/test/Normal009";
    option.filePath = filePath;
    option.bundleName = "abc";
    pref = PreferencesHelper::GetPreferences(option, errCode);

    if (isEnhance) {
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(IsFileExist(filePath), false);
        ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
    } else {
        ASSERT_EQ(errCode, E_NOT_SUPPORTED);
    }
}

/**
 * @tc.name: StorageTypeCombineTest010
 * @tc.desc: combine test, test GSKV mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest010, TestSize.Level0)
{
    // xml exists when GSKV mode
    // create xml firstly
    int errCode = E_OK;
    std::string filePath = "/data/test/Test010";
    Options option = Options(filePath, "", "");
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    ASSERT_EQ(IsFileExist(filePath + ".db"), false);

    // open with white list, it should be xml even in enhance
    option.bundleName = "abcuttestabc";
    option.isEnhance = true;
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    ASSERT_EQ(IsFileExist(filePath + ".db"), false);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

    // when not in white list
    option.bundleName = "abc";
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_NOT_SUPPORTED);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: StorageTypeCombineTest011
 * @tc.desc: combine test, test GSKV mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest011, TestSize.Level0)
{
    // GSKV exists, open with GSKV mode
    // create fake GSKV firstly
    int errCode = E_OK;
    std::string filePath = "/data/test/Test011";
    std::string filePathFakeKV = "/data/test/Test011.db";
    Options option = Options(filePathFakeKV, "", "");
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePathFakeKV), E_OK);
    ASSERT_EQ(IsFileExist(filePath), false);
    ASSERT_EQ(IsFileExist(filePathFakeKV), true);

    // open in white list when not enhance
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        option.bundleName = "uttest";
        option.isEnhance = true;
        option.filePath = filePath;
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        // when not white list
        option.bundleName = "abc";
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_NOT_SUPPORTED);
    }
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath + ".db"), E_OK);
}

/**
 * @tc.name: StorageTypeCombineTest012
 * @tc.desc: combine test, test GSKV mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest012, TestSize.Level0)
{
    // GSKV exists, open with GSKV mode
    // it should be GSKV enven not in white list
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        // create GSKV firstly
        int errCode = E_OK;
        std::string filePath = "/data/test/Test012";
        Options option = Options(filePath, "", "", true);
        std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath), false);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);

        option.bundleName = "uttest";
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath), false);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);

        option.bundleName = "abc";
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath), false);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
    }
}

/**
 * @tc.name: StorageTypeApiTest013
 * @tc.desc: api test, test GSKV mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeApiTest013, TestSize.Level0)
{
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        int errCode = E_OK;
        std::string filePath = "/data/test/Test013";
        Options option = Options(filePath, "", "", true);
        std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        for (int i = 0; i < 100; i++) {
            ASSERT_EQ(pref->PutString("test013_key_" + std::to_string(i), "test013_value_" + std::to_string(i)), E_OK);
        }
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        for (int i = 0; i < 100; i++) {
            std::string expValue = "test013_value_" + std::to_string(i);
            ASSERT_EQ(pref->GetString("test013_key_" + std::to_string(i), "def"), expValue);
        }
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        auto set = pref->GetAll();
        ASSERT_EQ(set.size(), 100);
        ASSERT_EQ(pref->Clear(), E_OK);
        auto set2 = pref->GetAll();
        ASSERT_EQ(set2.size(), 0);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
    }
}

/**
 * @tc.name: CacheSizeConfigTest001
 * @tc.desc: test GSKV Init with cacheSize=0 (hasCacheSize=true), should open db successfully without map file
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesStorageTypeTest, CacheSizeConfigTest001, TestSize.Level0)
{
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        return;
    }
    int errCode = E_OK;
    std::string filePath = "/data/test/CacheSizeTest001";
    Options option = Options(filePath, "com.hmos.uttest", "", true, 0, true);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(Access(filePath + ".db"), F_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: CacheSizeConfigTest002
 * @tc.desc: test GSKV Init with cacheSize=256 (hasCacheSize=true), should open db successfully
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesStorageTypeTest, CacheSizeConfigTest002, TestSize.Level0)
{
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        return;
    }
    int errCode = E_OK;
    std::string filePath = "/data/test/CacheSizeTest002";
    Options option = Options(filePath, "com.hmos.uttest", "", true, 256, true);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(Access(filePath + ".db"), F_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: CacheSizeConfigTest003
 * @tc.desc: test GSKV Init without cacheSize (hasCacheSize=false), behavior should be backward compatible
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesStorageTypeTest, CacheSizeConfigTest003, TestSize.Level0)
{
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        return;
    }
    int errCode = E_OK;
    std::string filePath = "/data/test/CacheSizeTest003";
    Options option = Options(filePath, "com.hmos.uttest", "", true);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(Access(filePath + ".db"), F_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: CacheSizeConfigTest004
 * @tc.desc: test GSKV Init with cacheSize=1112784 (max boundary), should open db successfully
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesStorageTypeTest, CacheSizeConfigTest004, TestSize.Level0)
{
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        return;
    }
    int errCode = E_OK;
    std::string filePath = "/data/test/CacheSizeTest004";
    Options option = Options(filePath, "com.hmos.uttest", "", true, 1112784, true);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(Access(filePath + ".db"), F_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: CacheSizeConfigTest005
 * @tc.desc: test Options struct cacheSize and hasCacheSize fields with different constructors
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesStorageTypeTest, CacheSizeConfigTest005, TestSize.Level0)
{
    Options opt1 = Options("/data/test/test", "com.test", "");
    EXPECT_EQ(opt1.cacheSize, 0u);
    EXPECT_EQ(opt1.hasCacheSize, false);

    Options opt2 = Options("/data/test/test", "com.test", "", true);
    EXPECT_EQ(opt2.cacheSize, 0u);
    EXPECT_EQ(opt2.hasCacheSize, false);

    Options opt3 = Options("/data/test/test", "com.test", "", true, 256, true);
    EXPECT_EQ(opt3.cacheSize, 256u);
    EXPECT_EQ(opt3.hasCacheSize, true);

    Options opt4 = Options("/data/test/test", "com.test", "", true, 0, true);
    EXPECT_EQ(opt4.cacheSize, 0u);
    EXPECT_EQ(opt4.hasCacheSize, true);
}

/**
 * @tc.name: CacheSizeXmlSilentIgnoreTest001
 * @tc.desc: test XML mode with cacheSize=256, cacheSize should be silently ignored
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesStorageTypeTest, CacheSizeXmlSilentIgnoreTest001, TestSize.Level0)
{
    int errCode = E_OK;
    std::string filePath = "/data/test/CacheSizeXmlTest001";
    Options option = Options(filePath, "com.hmos.uttest", "", false, 256, true);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(pref->GetString("key", "default"), "value");
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: CacheSizeXmlSilentIgnoreTest002
 * @tc.desc: test XML mode with cacheSize=0, cacheSize should be silently ignored
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesStorageTypeTest, CacheSizeXmlSilentIgnoreTest002, TestSize.Level0)
{
    int errCode = E_OK;
    std::string filePath = "/data/test/CacheSizeXmlTest002";
    Options option = Options(filePath, "com.hmos.uttest", "", false, 0, true);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(pref->GetString("key", "default"), "value");
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: CacheSizeUpgradeTest001
 * @tc.desc: upgrade scenario: default(no cacheSize) -> cacheSize=256, old data should be readable
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesStorageTypeTest, CacheSizeUpgradeTest001, TestSize.Level0)
{
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        return;
    }
    int errCode = E_OK;
    std::string filePath = "/data/test/CacheSizeUpgrade001";

    // Step1: open with default (no cacheSize), write data
    Options opt1 = Options(filePath, "com.hmos.uttest", "", true);
    std::shared_ptr<Preferences> pref1 = PreferencesHelper::GetPreferences(opt1, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref1->PutString("upgrade_key", "upgrade_value"), E_OK);
    ASSERT_EQ(pref1->PutInt("upgrade_num", 100), E_OK);
    ASSERT_EQ(pref1->FlushSync(), E_OK);

    // Step2: remove from cache
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

    // Step3: reopen with cacheSize=256, verify old data
    Options opt2 = Options(filePath, "com.hmos.uttest", "", true, 256, true);
    std::shared_ptr<Preferences> pref2 = PreferencesHelper::GetPreferences(opt2, errCode);
    ASSERT_EQ(errCode, E_OK);
    EXPECT_EQ(pref2->GetString("upgrade_key", "NOT_FOUND"), "upgrade_value");
    EXPECT_EQ(pref2->GetInt("upgrade_num", -1), 100);

    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: CacheSizeUpgradeTest002
 * @tc.desc: upgrade scenario: cacheSize=256 -> cacheSize=0, old data should be readable
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesStorageTypeTest, CacheSizeUpgradeTest002, TestSize.Level0)
{
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        return;
    }
    int errCode = E_OK;
    std::string filePath = "/data/test/CacheSizeUpgrade002";

    // Step1: open with cacheSize=256, write data
    Options opt1 = Options(filePath, "com.hmos.uttest", "", true, 256, true);
    std::shared_ptr<Preferences> pref1 = PreferencesHelper::GetPreferences(opt1, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref1->PutString("u2_key", "u2_value"), E_OK);
    ASSERT_EQ(pref1->PutInt("u2_num", 200), E_OK);
    ASSERT_EQ(pref1->FlushSync(), E_OK);

    // Step2: remove from cache
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

    // Step3: reopen with cacheSize=0, verify old data
    Options opt2 = Options(filePath, "com.hmos.uttest", "", true, 0, true);
    std::shared_ptr<Preferences> pref2 = PreferencesHelper::GetPreferences(opt2, errCode);
    ASSERT_EQ(errCode, E_OK);
    EXPECT_EQ(pref2->GetString("u2_key", "NOT_FOUND"), "u2_value");
    EXPECT_EQ(pref2->GetInt("u2_num", -1), 200);

    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: CacheSizeUpgradeTest003
 * @tc.desc: upgrade scenario: cacheSize=0 -> cacheSize=65536, old data should be readable
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesStorageTypeTest, CacheSizeUpgradeTest003, TestSize.Level0)
{
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        return;
    }
    int errCode = E_OK;
    std::string filePath = "/data/test/CacheSizeUpgrade003";

    // Step1: open with cacheSize=0, write data
    Options opt1 = Options(filePath, "com.hmos.uttest", "", true, 0, true);
    std::shared_ptr<Preferences> pref1 = PreferencesHelper::GetPreferences(opt1, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref1->PutString("u3_key", "u3_value"), E_OK);
    ASSERT_EQ(pref1->PutInt("u3_num", 300), E_OK);
    ASSERT_EQ(pref1->FlushSync(), E_OK);

    // Step2: remove from cache
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

    // Step3: reopen with cacheSize=65536, verify old data
    Options opt2 = Options(filePath, "com.hmos.uttest", "", true, 65536, true);
    std::shared_ptr<Preferences> pref2 = PreferencesHelper::GetPreferences(opt2, errCode);
    ASSERT_EQ(errCode, E_OK);
    EXPECT_EQ(pref2->GetString("u3_key", "NOT_FOUND"), "u3_value");
    EXPECT_EQ(pref2->GetInt("u3_num", -1), 300);

    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: CacheSizeChainedUpgradeTest
 * @tc.desc: chained upgrade: default -> 256 -> 0 -> 65536 -> default -> 1112784,
 *           each step removeFromCache and reopen, verify old data readable and write new data
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesStorageTypeTest, CacheSizeChainedUpgradeTest, TestSize.Level0)
{
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        return;
    }
    int errCode = E_OK;
    std::string filePath = "/data/test/CacheSizeChainedUpgrade";

    // chain of cacheSize configs: -1 means default (hasCacheSize=false)
    struct ChainConfig { int32_t cacheSize; bool hasCacheSize; };
    std::vector<ChainConfig> chain = {
        {0, false},   // default
        {256, true},
        {0, true},
        {65536, true},
        {0, false},   // default
        {1112784, true},
    };

    for (size_t i = 0; i < chain.size(); i++) {
        ChainConfig cfg = chain[i];
        Options opt = Options(filePath, "com.hmos.uttest", "", true, cfg.cacheSize, cfg.hasCacheSize);
        std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(opt, errCode);
        ASSERT_EQ(errCode, E_OK) << "step " << i << " open failed";

        if (i == 0) {
            // first step: write initial data
            ASSERT_EQ(pref->PutString("chain_key", "chain_value"), E_OK);
            ASSERT_EQ(pref->PutInt("chain_num", 1), E_OK);
            ASSERT_EQ(pref->FlushSync(), E_OK);
        } else {
            // verify old data
            EXPECT_EQ(pref->GetString("chain_key", "NOT_FOUND"), "chain_value");
            EXPECT_EQ(pref->GetInt("chain_num", -1), 1);
            // write step marker
            std::string stepKey = "step_" + std::to_string(i);
            std::string stepVal = "val_" + std::to_string(i);
            ASSERT_EQ(pref->PutString(stepKey, stepVal), E_OK);
            ASSERT_EQ(pref->FlushSync(), E_OK);
            // verify step marker
            EXPECT_EQ(pref->GetString(stepKey, "NOT_FOUND"), stepVal);
        }

        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    }

    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: CacheSizeReadWriteTest
 * @tc.desc: read/write verification under cacheSize config: put/get/hasKey/delete/clear with
 *           int/string types, verify data consistency across operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesStorageTypeTest, CacheSizeReadWriteTest, TestSize.Level0)
{
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        return;
    }
    int errCode = E_OK;
    std::string filePath = "/data/test/CacheSizeReadWrite";
    Options option = Options(filePath, "com.hmos.uttest", "", true, 65536, true);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);

    // put int and string
    ASSERT_EQ(pref->PutInt("int_key", 42), E_OK);
    ASSERT_EQ(pref->PutString("str_key", "hello_cacheSize"), E_OK);
    ASSERT_EQ(pref->PutInt("neg_key", -99), E_OK);
    ASSERT_EQ(pref->PutString("empty_key", ""), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);

    // get and verify
    EXPECT_EQ(pref->GetInt("int_key", -1), 42);
    EXPECT_EQ(pref->GetString("str_key", "default"), "hello_cacheSize");
    EXPECT_EQ(pref->GetInt("neg_key", 0), -99);
    EXPECT_EQ(pref->GetString("empty_key", "default"), "");

    // hasKey
    EXPECT_TRUE(pref->HasKey("int_key"));
    EXPECT_TRUE(pref->HasKey("str_key"));
    EXPECT_FALSE(pref->HasKey("nonexistent_key"));

    // delete and verify
    ASSERT_EQ(pref->Delete("int_key"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    EXPECT_FALSE(pref->HasKey("int_key"));
    EXPECT_EQ(pref->GetInt("int_key", -1), -1); // default returned
    // other keys still present
    EXPECT_TRUE(pref->HasKey("str_key"));

    // clear all
    ASSERT_EQ(pref->Clear(), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    auto all = pref->GetAll();
    EXPECT_EQ(static_cast<int>(all.size()), 0);
    EXPECT_FALSE(pref->HasKey("str_key"));

    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: CacheSizeUpgradeReadWriteTest
 * @tc.desc: upgrade + read/write cross-validation: write with cacheSize=256, upgrade to
 *           cacheSize=0, verify old data + write new data + upgrade back to 65536, verify all
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesStorageTypeTest, CacheSizeUpgradeReadWriteTest, TestSize.Level0)
{
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        return;
    }
    int errCode = E_OK;
    std::string filePath = "/data/test/CacheSizeUpgradeRW";

    // Step1: cacheSize=256, write multiple data types
    Options opt1 = Options(filePath, "com.hmos.uttest", "", true, 256, true);
    std::shared_ptr<Preferences> pref1 = PreferencesHelper::GetPreferences(opt1, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref1->PutString("s1", "v1"), E_OK);
    ASSERT_EQ(pref1->PutInt("i1", 10), E_OK);
    ASSERT_EQ(pref1->PutString("s2", "v2"), E_OK);
    ASSERT_EQ(pref1->PutInt("i2", 20), E_OK);
    ASSERT_EQ(pref1->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

    // Step2: upgrade to cacheSize=0, verify old data + delete one + add new
    Options opt2 = Options(filePath, "com.hmos.uttest", "", true, 0, true);
    std::shared_ptr<Preferences> pref2 = PreferencesHelper::GetPreferences(opt2, errCode);
    ASSERT_EQ(errCode, E_OK);
    EXPECT_EQ(pref2->GetString("s1", "NF"), "v1");
    EXPECT_EQ(pref2->GetInt("i1", -1), 10);
    EXPECT_EQ(pref2->GetString("s2", "NF"), "v2");
    EXPECT_EQ(pref2->GetInt("i2", -1), 20);
    // delete s1, add s3
    ASSERT_EQ(pref2->Delete("s1"), E_OK);
    ASSERT_EQ(pref2->PutString("s3", "v3"), E_OK);
    ASSERT_EQ(pref2->FlushSync(), E_OK);
    EXPECT_FALSE(pref2->HasKey("s1"));
    EXPECT_TRUE(pref2->HasKey("s3"));
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

    // Step3: upgrade to cacheSize=65536, verify all remaining data
    Options opt3 = Options(filePath, "com.hmos.uttest", "", true, 65536, true);
    std::shared_ptr<Preferences> pref3 = PreferencesHelper::GetPreferences(opt3, errCode);
    ASSERT_EQ(errCode, E_OK);
    EXPECT_FALSE(pref3->HasKey("s1")); // deleted in step2
    EXPECT_EQ(pref3->GetInt("i1", -1), 10); // i1 still exists (only s1 was deleted)
    EXPECT_EQ(pref3->GetString("s2", "NF"), "v2");
    EXPECT_EQ(pref3->GetInt("i2", -1), 20);
    EXPECT_EQ(pref3->GetString("s3", "NF"), "v3"); // added in step2

    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}
} // namespace