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
class PreferencesNdkTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PreferencesNdkTest::SetUpTestCase(void)
{
    NdkTestUtils::CreateDirectoryRecursively("/data/test/");
}
void PreferencesNdkTest::TearDownTestCase(void) {}

void PreferencesNdkTest::SetUp(void)
{
    NdkTestUtils::CreateDirectoryRecursively("/data/test/");
}

void PreferencesNdkTest::TearDown(void) {}

enum class PrefDataType { UNASSIGNED, INT, STRING, BOOL };

const uint32_t INVALID_INDEX = 100;

static OH_PreferencesOption *GetCommonOption()
{
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    EXPECT_EQ(OH_PreferencesOption_SetFileName(option, "testdb"), PREFERENCES_OK);
    EXPECT_EQ(OH_PreferencesOption_SetBundleName(option, "com.uttest"), PREFERENCES_OK);
    EXPECT_EQ(OH_PreferencesOption_SetDataGroupId(option, "123"), PREFERENCES_OK);
    return option;
}

std::map<std::string, int> g_intDataMap = {
    {"ndktest_int_key_1", -2147483648},
    {"ndktest_int_key_2", -1},
    {"ndktest_int_key_3", 0},
    {"ndktest_int_key_4", 1},
    {"ndktest_int_key_5", 2147483647}
};

std::map<std::string, std::string> g_stringDataMap = {
    {"ndktest_string_key_1", "2679b2c70120214984b3aec34fc849dc996f40e3cdb60f3b3eaf8abe2559439a"},
    {"ndktest_string_key_2", "+88780079687688"},
    {"ndktest_string_key_3", "/data/storage/el2/base/files/Thumbnail_1717209543267.jpg"},
    {"ndktest_string_key_4", "A NEW PHONE"},
    {"ndktest_string_key_5", "https://upfile-drcn.platform.hicloud.com/"}
};

std::map<std::string, bool> g_boolDataMap = {
    {"ndktest_bool_key_1", true},
    {"ndktest_bool_key_2", false},
    {"ndktest_bool_key_3", false},
    {"ndktest_bool_key_4", true},
    {"ndktest_bool_key_5", true}
};

int g_changeNum = 0;
void DataChangeObserverCallback(void *context, const OH_PreferencesPair *pairs, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        const OH_PreferencesValue *pValue = OH_PreferencesPair_GetPreferencesValue(pairs, i);
        Preference_ValueType type = OH_PreferencesValue_GetValueType(pValue);
        const char *pKey = OH_PreferencesPair_GetKey(pairs, i);
        EXPECT_NE(pKey, nullptr);
        if (type == Preference_ValueType::PREFERENCE_TYPE_INT) {
            int intV = 0;
            OH_PreferencesValue_GetInt(pValue, &intV);
        } else if (type == Preference_ValueType::PREFERENCE_TYPE_BOOL) {
            bool boolV = false;
            OH_PreferencesValue_GetBool(pValue, &boolV);
        } else if (type == Preference_ValueType::PREFERENCE_TYPE_STRING) {
            char *stringV = nullptr;
            uint32_t len = 0;
            OH_PreferencesValue_GetString(pValue, &stringV, &len);
            OH_Preferences_FreeString(stringV);
        }
        g_changeNum++;
    }
}

int PreferencesFlush(OH_Preferences *preference)
{
    OH_PreferencesImpl *pref = static_cast<OH_PreferencesImpl *>(preference);
    std::shared_ptr<OHOS::NativePreferences::Preferences> nativePreferences = pref->GetNativePreferences();
    return nativePreferences->FlushSync();
}

void SetAllValuesWithCheck(OH_Preferences *pref)
{
    for (auto &[key, value] : g_intDataMap) {
        EXPECT_EQ(OH_Preferences_SetInt(pref, key.c_str(), value), PREFERENCES_OK);
        EXPECT_EQ(PreferencesFlush(pref), OHOS::NativePreferences::E_OK);
        int res = 0;
        EXPECT_EQ(OH_Preferences_GetInt(pref, key.c_str(), &res), PREFERENCES_OK);
        EXPECT_EQ(res, value);
    }
    for (auto &[key, value] : g_stringDataMap) {
        EXPECT_EQ(OH_Preferences_SetString(pref, key.c_str(), value.c_str()), PREFERENCES_OK);
        EXPECT_EQ(PreferencesFlush(pref), OHOS::NativePreferences::E_OK);
        char *res = nullptr;
        uint32_t len = 0;
        EXPECT_EQ(OH_Preferences_GetString(pref, key.c_str(), &res, &len), PREFERENCES_OK);
        EXPECT_EQ(strcmp(res, value.c_str()), 0);
        OH_Preferences_FreeString(res);
    }
    for (auto &[key, value] : g_boolDataMap) {
        EXPECT_EQ(OH_Preferences_SetBool(pref, key.c_str(), value), PREFERENCES_OK);
        EXPECT_EQ(PreferencesFlush(pref), OHOS::NativePreferences::E_OK);
        bool res;
        EXPECT_EQ(OH_Preferences_GetBool(pref, key.c_str(), &res), PREFERENCES_OK);
        EXPECT_EQ(res, value);
    }
}

void CheckTargetTypeValues(OH_Preferences *pref, bool exist, PrefDataType pdt)
{
    if (pdt == PrefDataType::INT) {
        for (auto &[key, value] : g_intDataMap) {
            int res;
            if (exist) {
                EXPECT_EQ(OH_Preferences_GetInt(pref, key.c_str(), &res), PREFERENCES_OK);
                EXPECT_EQ(res, value);
            } else {
                EXPECT_EQ(OH_Preferences_GetInt(pref, key.c_str(), &res), PREFERENCES_ERROR_KEY_NOT_FOUND);
            }
        }
    } else if (pdt == PrefDataType::STRING) {
        for (auto &[key, value] : g_stringDataMap) {
            char *res = nullptr;
            uint32_t len = 0;
            if (exist) {
                EXPECT_EQ(OH_Preferences_GetString(pref, key.c_str(), &res, &len), PREFERENCES_OK);
                EXPECT_EQ(strcmp(res, value.c_str()), 0);
            } else {
                EXPECT_EQ(OH_Preferences_GetString(pref, key.c_str(), &res, &len), PREFERENCES_ERROR_KEY_NOT_FOUND);
            }
            OH_Preferences_FreeString(res);
        }
    } else if (pdt == PrefDataType::BOOL) {
        for (auto &[key, value] : g_boolDataMap) {
            bool res;
            if (exist) {
                EXPECT_EQ(OH_Preferences_GetBool(pref, key.c_str(), &res), PREFERENCES_OK);
                EXPECT_EQ(res, value);
            } else {
                EXPECT_EQ(OH_Preferences_GetBool(pref, key.c_str(), &res), PREFERENCES_ERROR_KEY_NOT_FOUND);
            }
        }
    }
}

/**
 * @tc.name: NDKPreferencesGetTest_001
 * @tc.desc: 测试先put int类型的kv，再get相同的key，值相同
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetTest_001, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    SetAllValuesWithCheck(pref);

    const char *key = "test_key_int";
    EXPECT_EQ(OH_Preferences_SetInt(pref, key, 12), PREFERENCES_OK);
    int ret;
    EXPECT_EQ(OH_Preferences_GetInt(pref, key, &ret), PREFERENCES_OK);
    EXPECT_EQ(ret, 12);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesGetTest_002
 * @tc.desc: 测试先put string类型的kv，再get相同的key，值相同
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetTest_002, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    SetAllValuesWithCheck(pref);

    const char *key = "test_key_string";
    const char *value = "test_value";
    EXPECT_EQ(OH_Preferences_SetString(pref, key, value), PREFERENCES_OK);
    char *ret = nullptr;
    uint32_t len = 0;
    EXPECT_EQ(OH_Preferences_GetString(pref, key, &ret, &len), PREFERENCES_OK);
    EXPECT_EQ(strcmp(ret, value), 0);
    OH_Preferences_FreeString(ret);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesGetTest_003
 * @tc.desc: 测试先put bool类型的kv，再get相同的key，值相同
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetTest_003, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    SetAllValuesWithCheck(pref);

    const char *key = "test_key_bool";
    bool value = true;
    EXPECT_EQ(OH_Preferences_SetBool(pref, key, value), PREFERENCES_OK);
    bool ret;
    EXPECT_EQ(OH_Preferences_GetBool(pref, key, &ret), PREFERENCES_OK);
    EXPECT_EQ(ret, value);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesGetTest_004
 * @tc.desc: 测试get不存在的kv
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetTest_004, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    CheckTargetTypeValues(pref, false, PrefDataType::INT);
    CheckTargetTypeValues(pref, false, PrefDataType::STRING);
    CheckTargetTypeValues(pref, false, PrefDataType::BOOL);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesPutTest_001
 * @tc.desc: 测试先get不存在的kv，再put进kv，然后get
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesPutTest_001, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    CheckTargetTypeValues(pref, false, PrefDataType::INT);
    CheckTargetTypeValues(pref, false, PrefDataType::STRING);
    CheckTargetTypeValues(pref, false, PrefDataType::BOOL);

    SetAllValuesWithCheck(pref);

    CheckTargetTypeValues(pref, true, PrefDataType::INT);
    CheckTargetTypeValues(pref, true, PrefDataType::STRING);
    CheckTargetTypeValues(pref, true, PrefDataType::BOOL);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesUpdateTest_001
 * @tc.desc: 测试先put int类型的kv，然后get，然后再put新的值进行更新，再get
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesUpdateTest_001, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    SetAllValuesWithCheck(pref);

    const char *key = "ndktest_int_key_1";
    int newValue = 10;
    EXPECT_EQ(OH_Preferences_SetInt(pref, key, newValue), PREFERENCES_OK);
    int ret;
    EXPECT_EQ(OH_Preferences_GetInt(pref, key, &ret), PREFERENCES_OK);
    EXPECT_EQ(ret, newValue);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesUpdateTest_002
 * @tc.desc: 测试先put string类型的kv，然后get，然后再put新的值进行更新，再get
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesUpdateTest_002, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    SetAllValuesWithCheck(pref);

    const char *key = "ndktest_string_key_1";
    const char *newValue = "adlkj1#$&sdioj9i0i841a61aa4gh44o98()!@@.,.{:/',}";
    EXPECT_EQ(OH_Preferences_SetString(pref, key, newValue), PREFERENCES_OK);
    char *ret = nullptr;
    uint32_t len = 0;
    EXPECT_EQ(OH_Preferences_GetString(pref, key, &ret, &len), PREFERENCES_OK);
    EXPECT_EQ(strcmp(ret, newValue), 0);
    OH_Preferences_FreeString(ret);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesUpdateTest_003
 * @tc.desc: 测试先put bool类型的kv，然后get，然后再put新的值进行更新，再get
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesUpdateTest_003, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    SetAllValuesWithCheck(pref);

    const char *key = "ndktest_bool_key_1";
    bool newValue = false;
    EXPECT_EQ(OH_Preferences_SetBool(pref, key, newValue), PREFERENCES_OK);
    bool ret;
    EXPECT_EQ(OH_Preferences_GetBool(pref, key, &ret), PREFERENCES_OK);
    EXPECT_EQ(ret, newValue);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesDeleteTest_001
 * @tc.desc: test Delete exist key
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Liu Xiaolong
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesDeleteTest_001, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    SetAllValuesWithCheck(pref);

    for (auto &[key, value] : g_stringDataMap) {
        EXPECT_EQ(OH_Preferences_Delete(pref, key.c_str()), PREFERENCES_OK);
    }

    CheckTargetTypeValues(pref, true, PrefDataType::INT);
    CheckTargetTypeValues(pref, false, PrefDataType::STRING);
    CheckTargetTypeValues(pref, true, PrefDataType::BOOL);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesDeleteTest_002
 * @tc.desc: test Delete non-exist key
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Liu Xiaolong
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesDeleteTest_002, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    CheckTargetTypeValues(pref, false, PrefDataType::INT);

    for (auto &[key, value] : g_intDataMap) {
        EXPECT_EQ(OH_Preferences_Delete(pref, key.c_str()), PREFERENCES_OK);
    }

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

static void RegisterObsInFunc(OH_Preferences *pref)
{
    const char *keys[] = {"ndktest_int_key_1", "ndktest_string_key_1", "ndktest_bool_key_1"};

    int ret = OH_Preferences_RegisterDataObserver(pref, nullptr, DataChangeObserverCallback, keys, 3);
    ASSERT_EQ(ret, PREFERENCES_OK);
}

static void UnRegisterObsInFunc(OH_Preferences *pref)
{
    const char *keys[] = {"ndktest_int_key_1", "ndktest_string_key_1", "ndktest_bool_key_1"};

    int ret = OH_Preferences_UnregisterDataObserver(pref, nullptr, DataChangeObserverCallback, keys, 3);
    ASSERT_EQ(ret, PREFERENCES_OK);
}

/**
 * @tc.name: NDKPreferencesObserverTest_001
 * @tc.desc: test Observer
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Liu Xiaolong
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesObserverTest_001, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    RegisterObsInFunc(pref);

    SetAllValuesWithCheck(pref);

    for (auto &[key, value] : g_intDataMap) {
        EXPECT_EQ(OH_Preferences_Delete(pref, key.c_str()), PREFERENCES_OK);
        EXPECT_EQ(PreferencesFlush(pref), OHOS::NativePreferences::E_OK);
    }

    for (auto &[key, value] : g_stringDataMap) {
        const char *newValue = "update_string_value_109uokadnf894u5";
        EXPECT_EQ(OH_Preferences_SetString(pref, key.c_str(), newValue), PREFERENCES_OK);
        EXPECT_EQ(PreferencesFlush(pref), OHOS::NativePreferences::E_OK);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    EXPECT_EQ(g_changeNum, 5);

    UnRegisterObsInFunc(pref);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesObserverTest_002
 * @tc.desc: test Observer
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: bluhuang
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesObserverTest_002, TestSize.Level0)
{
    // cannot get callback when unregister
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    const char *keys[] = {"ndktest_int_key_1", "ndktest_string_key_1", "ndktest_bool_key_1"};
    g_changeNum = 0;
    int ret = OH_Preferences_RegisterDataObserver(pref, nullptr, DataChangeObserverCallback, keys, 3);
    ASSERT_EQ(ret, PREFERENCES_OK);
    const char *empty[] = {};
    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, DataChangeObserverCallback, empty, 0),
        PREFERENCES_OK);

    SetAllValuesWithCheck(pref);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    EXPECT_EQ(g_changeNum, 0);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);

    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesObserverTest_003
 * @tc.desc: test Observer
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: bluhuang
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesObserverTest_003, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    const char *keys[] = {"ndktest_int_key_1", "ndktest_string_key_1", "ndktest_bool_key_1"};
    g_changeNum = 0;
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(nullptr, nullptr, DataChangeObserverCallback, keys, 3),
        PREFERENCES_ERROR_INVALID_PARAM);
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, nullptr, nullptr, keys, 3), PREFERENCES_ERROR_INVALID_PARAM);
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, nullptr, DataChangeObserverCallback, nullptr, 3),
        PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(nullptr, nullptr, DataChangeObserverCallback, keys, 0),
        PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, nullptr, keys, 0),
        PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, DataChangeObserverCallback, nullptr, 0),
        PREFERENCES_ERROR_INVALID_PARAM);
}

/**
 * @tc.name: NDKPreferencesObserverTest_004
 * @tc.desc: test Observer
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: bluhuang
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesObserverTest_004, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    const char *keys1[] = {"ndktest_int_key_1", "ndktest_string_key_1", "ndktest_bool_key_1"};
    g_changeNum = 0;
    double obj = 1.1;
    void *context1 = &obj;
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, (void*) context1, DataChangeObserverCallback, keys1, 3),
        PREFERENCES_OK);

    const char *keys2[] = {"ndktest_int_key_5"};
    double obj2 = 2.2;
    void *context2 = &obj2;
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, (void*) context2, DataChangeObserverCallback, keys2, 1),
        PREFERENCES_OK);
    SetAllValuesWithCheck(pref);

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    EXPECT_EQ(g_changeNum, 4);

    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, DataChangeObserverCallback, keys1, 3),
        PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, DataChangeObserverCallback, keys2, 1),
        PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);

    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesObserverTest_005
 * @tc.desc: test Observer
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: bluhuang
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesObserverTest_005, TestSize.Level0)
{
    // cancel part of all registerd key
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    const char *keys[] = {"ndktest_int_key_1", "ndktest_string_key_1", "ndktest_bool_key_1"};
    g_changeNum = 0;
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, nullptr, DataChangeObserverCallback, keys, 3),
        PREFERENCES_OK);
    const char *cancel[] = {"ndktest_bool_key_1"};
    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, DataChangeObserverCallback, cancel, 1),
        PREFERENCES_OK);

    SetAllValuesWithCheck(pref);

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    EXPECT_EQ(g_changeNum, 2);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

void NullTestCallback(void *context, const OH_PreferencesPair *pairs, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        EXPECT_EQ(OH_PreferencesPair_GetPreferencesValue(nullptr, INVALID_INDEX), nullptr);
        EXPECT_EQ(OH_PreferencesPair_GetPreferencesValue(pairs, INVALID_INDEX), nullptr);

        EXPECT_EQ(OH_PreferencesValue_GetValueType(nullptr), Preference_ValueType::PREFERENCE_TYPE_NULL);

        EXPECT_EQ(OH_PreferencesPair_GetKey(nullptr, INVALID_INDEX), nullptr);
        EXPECT_EQ(OH_PreferencesPair_GetKey(pairs, INVALID_INDEX), nullptr);

        const OH_PreferencesValue *pValue = OH_PreferencesPair_GetPreferencesValue(pairs, i);
        Preference_ValueType type = OH_PreferencesValue_GetValueType(pValue);
        const char *pKey = OH_PreferencesPair_GetKey(pairs, i);
        EXPECT_NE(pKey, nullptr);
        if (type == Preference_ValueType::PREFERENCE_TYPE_INT) {
            EXPECT_EQ(OH_PreferencesValue_GetInt(nullptr, nullptr), PREFERENCES_ERROR_INVALID_PARAM);
            EXPECT_EQ(OH_PreferencesValue_GetInt(pValue, nullptr), PREFERENCES_ERROR_INVALID_PARAM);

            bool boolV = false;
            EXPECT_EQ(OH_PreferencesValue_GetBool(pValue, &boolV), PREFERENCES_ERROR_KEY_NOT_FOUND);
        } else if (type == Preference_ValueType::PREFERENCE_TYPE_BOOL) {
            EXPECT_EQ(OH_PreferencesValue_GetBool(nullptr, nullptr), PREFERENCES_ERROR_INVALID_PARAM);
            EXPECT_EQ(OH_PreferencesValue_GetBool(pValue, nullptr), PREFERENCES_ERROR_INVALID_PARAM);

            char *stringV = nullptr;
            uint32_t len = 0;
            EXPECT_EQ(OH_PreferencesValue_GetString(pValue, &stringV, &len), PREFERENCES_ERROR_KEY_NOT_FOUND);
        } else if (type == Preference_ValueType::PREFERENCE_TYPE_STRING) {
            char *stringV = nullptr;
            EXPECT_EQ(OH_PreferencesValue_GetString(nullptr, nullptr, nullptr), PREFERENCES_ERROR_INVALID_PARAM);
            EXPECT_EQ(OH_PreferencesValue_GetString(pValue, nullptr, nullptr), PREFERENCES_ERROR_INVALID_PARAM);
            EXPECT_EQ(OH_PreferencesValue_GetString(pValue, &stringV, nullptr), PREFERENCES_ERROR_INVALID_PARAM);

            int intV = 0;
            EXPECT_EQ(OH_PreferencesValue_GetInt(pValue, &intV), PREFERENCES_ERROR_KEY_NOT_FOUND);
        }
    }
}

/**
 * @tc.name: NDKPreferencesNullInputTest_001
 * @tc.desc: test NULL Input
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Liu Xiaolong
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesNullInputTest_001, TestSize.Level0)
{
    OH_Preferences_FreeString(nullptr);

    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = OH_PreferencesOption_Create();

    EXPECT_EQ(OH_PreferencesOption_SetFileName(nullptr, nullptr), PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_PreferencesOption_SetFileName(option, nullptr), PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_PreferencesOption_SetFileName(option, ""), PREFERENCES_ERROR_INVALID_PARAM);

    EXPECT_EQ(OH_PreferencesOption_SetBundleName(nullptr, nullptr), PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_PreferencesOption_SetBundleName(option, nullptr), PREFERENCES_ERROR_INVALID_PARAM);

    EXPECT_EQ(OH_PreferencesOption_SetDataGroupId(nullptr, nullptr), PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_PreferencesOption_SetDataGroupId(option, nullptr), PREFERENCES_ERROR_INVALID_PARAM);

    EXPECT_EQ(OH_PreferencesOption_Destroy(nullptr), PREFERENCES_ERROR_INVALID_PARAM);

    EXPECT_EQ(OH_PreferencesOption_SetFileName(option, "testdb"), PREFERENCES_OK);
    EXPECT_EQ(OH_PreferencesOption_SetBundleName(option, "com.uttest"), PREFERENCES_OK);
    EXPECT_EQ(OH_PreferencesOption_SetDataGroupId(option, "123"), PREFERENCES_OK);
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    const char *keys[] = {"ndktest_int_key_1", "ndktest_string_key_1", "ndktest_bool_key_1"};
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, nullptr, NullTestCallback, keys, 3), PREFERENCES_OK);

    SetAllValuesWithCheck(pref);

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, NullTestCallback, keys, 3), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);

    EXPECT_EQ(OH_Preferences_Close(nullptr), PREFERENCES_ERROR_INVALID_PARAM);

    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}


/**
 * @tc.name: NDKPreferencesDeletePreferencesTest_001
 * @tc.desc: Test OH_Preferences_DeletePreferences with null and invalid parameters
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesDeletePreferencesTest_001, TestSize.Level0)
{
    int ret = OH_Preferences_DeletePreferences(nullptr);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);

    OH_PreferencesOption* option = OH_PreferencesOption_Create();
    ASSERT_NE(option, nullptr);

    EXPECT_EQ(OH_PreferencesOption_SetBundleName(option, "com.test"), PREFERENCES_OK);

    ret = OH_Preferences_DeletePreferences(option);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    (void)OH_PreferencesOption_Destroy(option);
}

/**
 * @tc.name: NDKPreferencesDeletePreferencesTest_002
 * @tc.desc: Test OH_Preferences_DeletePreferences with valid parameters
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesDeletePreferencesTest_002, TestSize.Level0)
{
    // First create a preferences file
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    EXPECT_EQ(OH_Preferences_SetInt(pref, "test_key", 123), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);

    int ret = OH_Preferences_DeletePreferences(option);
    EXPECT_EQ(ret, PREFERENCES_OK);

    (void)OH_PreferencesOption_Destroy(option);
}

/**
 * @tc.name: NDKPreferencesSetGetValueTest_001
 * @tc.desc: Test OH_Preferences_SetValue and OH_Preferences_GetValue with null parameters
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesSetGetValueTest_001, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    ASSERT_NE(value, nullptr);

    EXPECT_EQ(OH_Preferences_SetValue(nullptr, "key", value), PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_Preferences_SetValue(pref, nullptr, value), PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_Preferences_SetValue(pref, "key", nullptr), PREFERENCES_ERROR_INVALID_PARAM);

    OH_PreferencesValue* outValue = nullptr;
    EXPECT_EQ(OH_Preferences_GetValue(nullptr, "key", &outValue), PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_Preferences_GetValue(pref, nullptr, &outValue), PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_Preferences_GetValue(pref, "key", nullptr), PREFERENCES_ERROR_INVALID_PARAM);

    OH_PreferencesValue_Destroy(value);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesSetGetValueTest_002
 * @tc.desc: Test OH_Preferences_SetValue and OH_Preferences_GetValue with different data types
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesSetGetValueTest_002, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    
    // Test int value
    OH_PreferencesValue* intValue = OH_PreferencesValue_Create();
    ASSERT_NE(intValue, nullptr);
    EXPECT_EQ(OH_PreferencesValue_SetInt(intValue, 456), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_SetValue(pref, "int_key", intValue), PREFERENCES_OK);
    
    OH_PreferencesValue* getIntValue = OH_PreferencesValue_Create();
    EXPECT_EQ(OH_Preferences_GetValue(pref, "int_key", &getIntValue), PREFERENCES_OK);
    ASSERT_NE(getIntValue, nullptr);

    int intVal = 0;
    EXPECT_EQ(OH_PreferencesValue_GetInt(getIntValue, &intVal), PREFERENCES_OK);
    EXPECT_EQ(intVal, 456);
    OH_PreferencesValue_Destroy(getIntValue);

    // Test string value
    OH_PreferencesValue* stringValue = OH_PreferencesValue_Create();
    ASSERT_NE(stringValue, nullptr);
    EXPECT_EQ(OH_PreferencesValue_SetString(stringValue, "test_string"), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_SetValue(pref, "string_key", stringValue), PREFERENCES_OK);

    OH_PreferencesValue* getStringValue = OH_PreferencesValue_Create();
    EXPECT_EQ(OH_Preferences_GetValue(pref, "string_key", &getStringValue), PREFERENCES_OK);
    ASSERT_NE(getStringValue, nullptr);

    char* strVal = nullptr;
    uint32_t len = 0;
    EXPECT_EQ(OH_PreferencesValue_GetString(stringValue, &strVal, &len), PREFERENCES_OK);
    EXPECT_STREQ(strVal, "test_string");
    OH_Preferences_FreeString(strVal);
    OH_PreferencesValue_Destroy(getStringValue);

    // Test bool value
    OH_PreferencesValue* boolValue = OH_PreferencesValue_Create();
    ASSERT_NE(boolValue, nullptr);
    EXPECT_EQ(OH_PreferencesValue_SetBool(boolValue, true), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_SetValue(pref, "bool_key", boolValue), PREFERENCES_OK);
    OH_PreferencesValue* getBoolValue = OH_PreferencesValue_Create();
    EXPECT_EQ(OH_Preferences_GetValue(pref, "bool_key", &getBoolValue), PREFERENCES_OK);
    ASSERT_NE(getBoolValue, nullptr);

    OH_PreferencesValue_Destroy(intValue);
    OH_PreferencesValue_Destroy(stringValue);
    OH_PreferencesValue_Destroy(boolValue);
    OH_PreferencesValue_Destroy(getBoolValue);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesSetGetValueTest_003
 * @tc.desc: Test OH_Preferences_GetValue with non-existent key
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesSetGetValueTest_003, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_EQ(OH_Preferences_GetValue(pref, "non_existent_key", &value), PREFERENCES_OK);
    ASSERT_NE(value, nullptr);

    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_NULL);

    OH_PreferencesValue_Destroy(value);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesGetAllTest_001
 * @tc.desc: Test OH_Preferences_GetAll with null parameters
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetAllTest_001, TestSize.Level0)
{
    OH_PreferencesPair* pairs = nullptr;
    uint32_t count = 0;
    EXPECT_EQ(OH_Preferences_GetAll(nullptr, &pairs, &count), PREFERENCES_ERROR_INVALID_PARAM);
    
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    
    EXPECT_EQ(OH_Preferences_GetAll(pref, nullptr, &count), PREFERENCES_ERROR_INVALID_PARAM);
    
    EXPECT_EQ(OH_Preferences_GetAll(pref, &pairs, nullptr), PREFERENCES_ERROR_INVALID_PARAM);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesGetAllTest_002
 * @tc.desc: Test OH_Preferences_GetAll with empty database
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetAllTest_002, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    OH_PreferencesPair* pairs = nullptr;
    uint32_t count = 0;
    int ret = OH_Preferences_GetAll(pref, &pairs, &count);

    EXPECT_EQ(ret, PREFERENCES_ERROR_KEY_NOT_FOUND);
    EXPECT_EQ(pairs, nullptr);
    EXPECT_EQ(count, 0u);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesGetAllTest_003
 * @tc.desc: Test OH_Preferences_GetAll with data in database
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetAllTest_003, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    SetAllValuesWithCheck(pref);

    OH_PreferencesPair* pairs = nullptr;
    uint32_t count = 0;
    int ret = OH_Preferences_GetAll(pref, &pairs, &count);
    
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_NE(pairs, nullptr);
    EXPECT_GT(count, 0u);

    uint32_t expectedCount = g_intDataMap.size() + g_stringDataMap.size() + g_boolDataMap.size();
    EXPECT_EQ(count, expectedCount);

    if (pairs != nullptr) {
        OH_PreferencesPair_Destroy(pairs, count);
    }

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
    OH_PreferencesPair_Destroy(nullptr, 0);
}

/**
 * @tc.name: NDKPreferencesHasKeyTest_001
 * @tc.desc: Test OH_Preferences_HasKey with null parameters
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesHasKeyTest_001, TestSize.Level0)
{
    bool result = OH_Preferences_HasKey(nullptr, "test_key");
    EXPECT_EQ(result, false);

    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    
    result = OH_Preferences_HasKey(pref, nullptr);
    EXPECT_EQ(result, false);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesHasKeyTest_002
 * @tc.desc: Test OH_Preferences_HasKey with existing and non-existing keys
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesHasKeyTest_002, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    
    bool result = OH_Preferences_HasKey(pref, "non_existent_key");
    EXPECT_EQ(result, false);
    EXPECT_EQ(OH_Preferences_SetInt(pref, "test_key", 123), PREFERENCES_OK);
    result = OH_Preferences_HasKey(pref, "test_key");
    EXPECT_EQ(result, true);
    result = OH_Preferences_HasKey(pref, "TEST_KEY");
    EXPECT_EQ(result, false);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesFlushTest_001
 * @tc.desc: Test OH_Preferences_Flush with null parameters
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesFlushTest_001, TestSize.Level0)
{
    EXPECT_EQ(OH_Preferences_Flush(nullptr), PREFERENCES_ERROR_INVALID_PARAM);
}

/**
 * @tc.name: NDKPreferencesFlushTest_002
 * @tc.desc: Test OH_Preferences_Flush with valid preference
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesFlushTest_002, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    EXPECT_EQ(OH_Preferences_SetInt(pref, "flush_test_key", 789), PREFERENCES_OK);

    EXPECT_EQ(OH_Preferences_Flush(pref), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    option = GetCommonOption();
    pref = OH_Preferences_Open(option, &errCode);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    int value = 0;
    EXPECT_EQ(OH_Preferences_GetInt(pref, "flush_test_key", &value), PREFERENCES_OK);
    EXPECT_EQ(value, 789);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesClearCacheTest_001
 * @tc.desc: Test OH_Preferences_ClearCache with null parameters
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesClearCacheTest_001, TestSize.Level0)
{
    // Test with null preference
    EXPECT_EQ(OH_Preferences_ClearCache(nullptr), PREFERENCES_ERROR_INVALID_PARAM);
}

/**
 * @tc.name: NDKPreferencesClearCacheTest_002
 * @tc.desc: Test OH_Preferences_ClearCache with valid preference
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesClearCacheTest_002, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    SetAllValuesWithCheck(pref);

    EXPECT_EQ(OH_Preferences_ClearCache(pref), PREFERENCES_OK);

    for (auto &[key, value] : g_intDataMap) {
        EXPECT_FALSE(OH_Preferences_HasKey(pref, key.c_str()));
    }

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesMultiProcessObserverTest_001
 * @tc.desc: Test multi-process observer registration with null parameters
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesMultiProcessObserverTest_001, TestSize.Level0)
{
    // Test Register with null parameters
    EXPECT_EQ(OH_Preferences_RegisterMultiProcessDataObserver(nullptr, nullptr, DataChangeObserverCallback),
        PREFERENCES_ERROR_INVALID_PARAM);

    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    EXPECT_EQ(OH_Preferences_RegisterMultiProcessDataObserver(pref, nullptr, nullptr),
        PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_Preferences_UnregisterMultiProcessDataObserver(nullptr, nullptr, DataChangeObserverCallback),
        PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_Preferences_UnregisterMultiProcessDataObserver(pref, nullptr, nullptr),
        PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesMultiProcessObserverTest_002
 * @tc.desc: Test multi-process observer registration and unregistration
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesMultiProcessObserverTest_002, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    int ret = OH_Preferences_RegisterMultiProcessDataObserver(pref, nullptr, DataChangeObserverCallback);
    EXPECT_TRUE(ret == PREFERENCES_OK || ret == PREFERENCES_ERROR_STORAGE);
    if (ret == PREFERENCES_OK) {
        EXPECT_EQ(OH_Preferences_UnregisterMultiProcessDataObserver(pref, nullptr, DataChangeObserverCallback),
            PREFERENCES_OK);
    }

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesMultiProcessObserverTest_003
 * @tc.desc: Test multi-process observer with context
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesMultiProcessObserverTest_003, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);


    int contextData = 42;
    int ret = OH_Preferences_RegisterMultiProcessDataObserver(pref, &contextData, DataChangeObserverCallback);

    if (ret == PREFERENCES_OK) {
        EXPECT_EQ(OH_Preferences_UnregisterMultiProcessDataObserver(pref, &contextData, DataChangeObserverCallback),
            PREFERENCES_OK);
        int differentContext = 100;
        EXPECT_EQ(OH_Preferences_UnregisterMultiProcessDataObserver(pref, &differentContext,
            DataChangeObserverCallback), PREFERENCES_OK);
    }

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesGetAllTest_004
 * @tc.desc: Test OH_Preferences_GetAll memory management with multiple key-value pairs
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetAllTest_004, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    for (int i = 0; i < 50; i++) {
        std::string key = "test_key_" + std::to_string(i);
        std::string value = "test_value_" + std::to_string(i);
        EXPECT_EQ(OH_Preferences_SetString(pref, key.c_str(), value.c_str()), PREFERENCES_OK);
        EXPECT_EQ(OH_Preferences_Flush(pref), PREFERENCES_OK);
    }

    OH_PreferencesPair* pairs = nullptr;
    uint32_t count = 0;
    int ret = OH_Preferences_GetAll(pref, &pairs, &count);

    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_NE(pairs, nullptr);
    EXPECT_EQ(count, 50u);

    for (uint32_t i = 0; i < count; i++) {
        const char *key = OH_PreferencesPair_GetKey(pairs, i);
        EXPECT_NE(key, nullptr);
        const OH_PreferencesValue *value = OH_PreferencesPair_GetPreferencesValue(pairs, i);
        EXPECT_NE(value, nullptr);
    }

    if (pairs != nullptr) {
        OH_PreferencesPair_Destroy(pairs, count);
    }

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesGetAllTest_005
 * @tc.desc: Test OH_Preferences_GetAll with basic value types
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetAllTest_005, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_SetInt(pref, "int_key", 12345), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Flush(pref), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_SetBool(pref, "bool_key", true), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Flush(pref), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_SetString(pref, "string_key", "test_string"), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Flush(pref), PREFERENCES_OK);
    OH_PreferencesPair* pairs = nullptr;
    uint32_t count = 0;
    int ret = OH_Preferences_GetAll(pref, &pairs, &count);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_NE(pairs, nullptr);
    EXPECT_EQ(count, 3u);
    for (uint32_t i = 0; i < count; i++) {
        const char *key = OH_PreferencesPair_GetKey(pairs, i);
        if (key != nullptr) {
            std::string keyStr(key);
            const OH_PreferencesValue *value = OH_PreferencesPair_GetPreferencesValue(pairs, i);
            if (keyStr == "int_key") {
                int intV = 0;
                EXPECT_EQ(OH_PreferencesValue_GetInt(value, &intV), PREFERENCES_OK);
                EXPECT_EQ(intV, 12345);
            }
            if (keyStr == "bool_key") {
                bool boolV = false;
                EXPECT_EQ(OH_PreferencesValue_GetBool(value, &boolV), PREFERENCES_OK);
                EXPECT_EQ(boolV, true);
            }
            if (keyStr == "string_key") {
                char *stringV = nullptr;
                uint32_t len = 0;
                EXPECT_EQ(OH_PreferencesValue_GetString(value, &stringV, &len), PREFERENCES_OK);
                EXPECT_STREQ(stringV, "test_string");
                OH_Preferences_FreeString(stringV);
            }
        }
    }
    if (pairs != nullptr) {
        OH_PreferencesPair_Destroy(pairs, count);
    }
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesGetAllTest_006
 * @tc.desc: Test OH_Preferences_GetAll value verification
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetAllTest_006, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption* option = GetCommonOption();
    OH_Preferences* pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_SetInt(pref, "test_int", 99999), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_SetString(pref, "test_string", "hello"), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Flush(pref), PREFERENCES_OK);
    OH_PreferencesPair* pairs = nullptr;
    uint32_t count = 0;
    int ret = OH_Preferences_GetAll(pref, &pairs, &count);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_NE(pairs, nullptr);
    EXPECT_EQ(count, 2u);
    bool intVCorrect = false;
    bool stringVCorrect = false;
    for (uint32_t i = 0; i < count; i++) {
        const char *key = OH_PreferencesPair_GetKey(pairs, i);
        if (key != nullptr) {
            std::string keyStr(key);
            const OH_PreferencesValue *value = OH_PreferencesPair_GetPreferencesValue(pairs, i);
            if (keyStr == "test_int") {
                int intV = 0;
                EXPECT_EQ(OH_PreferencesValue_GetInt(value, &intV), PREFERENCES_OK);
                intV == 99999 ? intVCorrect = true : intVCorrect = false;
            }
            if (keyStr == "test_string") {
                char *stringV = nullptr;
                uint32_t len = 0;
                EXPECT_EQ(OH_PreferencesValue_GetString(value, &stringV, &len), PREFERENCES_OK);
                (stringV != nullptr && std::string(stringV) == "hello") ?
                    stringVCorrect = true : stringVCorrect = false;
                OH_Preferences_FreeString(stringV);
            }
        }
    }
    EXPECT_TRUE(intVCorrect);
    EXPECT_TRUE(stringVCorrect);
    if (pairs != nullptr) {
        OH_PreferencesPair_Destroy(pairs, count);
    }
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

static std::vector<std::string> g_receivedKeys;
static std::mutex g_receivedKeysMutex;

void DataChangeObserverCallbackImmediateUse(void *context, const OH_PreferencesPair *pairs, uint32_t count)
{
    std::lock_guard<std::mutex> lock(g_receivedKeysMutex);
    for (uint32_t i = 0; i < count; i++) {
        const char *pKey = OH_PreferencesPair_GetKey(pairs, i);
        EXPECT_NE(pKey, nullptr);
        if (pKey != nullptr) {
            g_receivedKeys.push_back(std::string(pKey));
        }
    }
}

HWTEST_F(PreferencesNdkTest, NDKPreferencesObserverCallbackTest_001, TestSize.Level0)
{
    g_receivedKeys.clear();
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    const char *keys[] = {"callback_test_key_1", "callback_test_key_2", "callback_test_key_3"};
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, nullptr, DataChangeObserverCallbackImmediateUse, keys, 3),
        PREFERENCES_OK);

    EXPECT_EQ(OH_Preferences_SetInt(pref, "callback_test_key_1", 100), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_SetString(pref, "callback_test_key_2", "test_string"), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_SetBool(pref, "callback_test_key_3", true), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Flush(pref), PREFERENCES_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    EXPECT_EQ(g_receivedKeys.size(), 3u);
    EXPECT_TRUE(std::find(g_receivedKeys.begin(), g_receivedKeys.end(), "callback_test_key_1") != g_receivedKeys.end());
    EXPECT_TRUE(std::find(g_receivedKeys.begin(), g_receivedKeys.end(), "callback_test_key_2") != g_receivedKeys.end());
    EXPECT_TRUE(std::find(g_receivedKeys.begin(), g_receivedKeys.end(), "callback_test_key_3") != g_receivedKeys.end());

    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, DataChangeObserverCallbackImmediateUse, keys, 3),
        PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

static int g_callbackCount = 0;
static std::string g_lastReceivedKey;

void DataChangeObserverCallbackSingleKey(void *context, const OH_PreferencesPair *pairs, uint32_t count)
{
    EXPECT_EQ(count, 1u);
    const char *pKey = OH_PreferencesPair_GetKey(pairs, 0);
    EXPECT_NE(pKey, nullptr);
    if (pKey != nullptr) {
        g_lastReceivedKey = std::string(pKey);
    }
    g_callbackCount++;
}

HWTEST_F(PreferencesNdkTest, NDKPreferencesObserverCallbackTest_002, TestSize.Level0)
{
    g_callbackCount = 0;
    g_lastReceivedKey.clear();
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    const char *keys[] = {"single_key_test"};
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, nullptr, DataChangeObserverCallbackSingleKey, keys, 1),
        PREFERENCES_OK);

    EXPECT_EQ(OH_Preferences_SetInt(pref, "single_key_test", 42), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Flush(pref), PREFERENCES_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    EXPECT_EQ(g_callbackCount, 1);
    EXPECT_EQ(g_lastReceivedKey, "single_key_test");

    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, DataChangeObserverCallbackSingleKey, keys, 1),
        PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

static std::map<std::string, int> g_receivedIntValues;
static std::map<std::string, std::string> g_receivedStringValues;
static std::map<std::string, bool> g_receivedBoolValues;
static std::mutex g_receivedValuesMutex;

void DataChangeObserverCallbackValueType(void *context, const OH_PreferencesPair *pairs, uint32_t count)
{
    std::lock_guard<std::mutex> lock(g_receivedValuesMutex);
    for (uint32_t i = 0; i < count; i++) {
        const char *pKey = OH_PreferencesPair_GetKey(pairs, i);
        EXPECT_NE(pKey, nullptr);
        if (pKey == nullptr) {
            continue;
        }
        const OH_PreferencesValue *pValue = OH_PreferencesPair_GetPreferencesValue(pairs, i);
        Preference_ValueType type = OH_PreferencesValue_GetValueType(pValue);
        if (type == Preference_ValueType::PREFERENCE_TYPE_INT) {
            int intV = 0;
            EXPECT_EQ(OH_PreferencesValue_GetInt(pValue, &intV), PREFERENCES_OK);
            g_receivedIntValues[pKey] = intV;
        } else if (type == Preference_ValueType::PREFERENCE_TYPE_STRING) {
            char *stringV = nullptr;
            uint32_t len = 0;
            EXPECT_EQ(OH_PreferencesValue_GetString(pValue, &stringV, &len), PREFERENCES_OK);
            if (stringV != nullptr) {
                g_receivedStringValues[pKey] = std::string(stringV);
                OH_Preferences_FreeString(stringV);
            }
        } else if (type == Preference_ValueType::PREFERENCE_TYPE_BOOL) {
            bool boolV = false;
            EXPECT_EQ(OH_PreferencesValue_GetBool(pValue, &boolV), PREFERENCES_OK);
            g_receivedBoolValues[pKey] = boolV;
        }
    }
}

HWTEST_F(PreferencesNdkTest, NDKPreferencesObserverCallbackTest_003, TestSize.Level0)
{
    g_receivedIntValues.clear();
    g_receivedStringValues.clear();
    g_receivedBoolValues.clear();
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    const char *keys[] = {"int_key", "string_key", "bool_key"};
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, nullptr, DataChangeObserverCallbackValueType, keys, 3),
        PREFERENCES_OK);

    EXPECT_EQ(OH_Preferences_SetInt(pref, "int_key", 12345), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_SetString(pref, "string_key", "callback_test_value"), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_SetBool(pref, "bool_key", false), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Flush(pref), PREFERENCES_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    EXPECT_EQ(g_receivedIntValues.size(), 1u);
    EXPECT_EQ(g_receivedIntValues["int_key"], 12345);

    EXPECT_EQ(g_receivedStringValues.size(), 1u);
    EXPECT_EQ(g_receivedStringValues["string_key"], "callback_test_value");

    EXPECT_EQ(g_receivedBoolValues.size(), 1u);
    EXPECT_EQ(g_receivedBoolValues["bool_key"], false);

    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, DataChangeObserverCallbackValueType, keys, 3),
        PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}
}
