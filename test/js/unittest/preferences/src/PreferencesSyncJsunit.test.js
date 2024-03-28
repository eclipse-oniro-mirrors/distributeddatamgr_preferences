/*
* Copyright (c) 2023 Huawei Device Co., Ltd.
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
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import data_preferences from '@ohos.data.preferences'
import featureAbility from '@ohos.ability.featureAbility';

const NAME = 'test_preferences';
const KEY_TEST_INT_ELEMENT = 'key_test_int';
const KEY_TEST_LONG_ELEMENT = 'key_test_long';
const KEY_TEST_FLOAT_ELEMENT = 'key_test_float';
const KEY_TEST_BOOLEAN_ELEMENT = 'key_test_boolean';
const KEY_TEST_STRING_ELEMENT = 'key_test_string';
const KEY_TEST_NUMBER_ARRAY_ELEMENT = 'key_test_number_array'
const KEY_TEST_STRING_ARRAY_ELEMENT = 'key_test_string_array'
const KEY_TEST_BOOL_ARRAY_ELEMENT = 'key_test_bool_array'
const KEY_TEST_BIGINT = 'key_test_bigint'
var mPreferences;
var context;

describe('preferencesSyncTest', function () {
    beforeAll(function () {
        console.info('beforeAll');
        context = featureAbility.getContext();
    })

    beforeEach(async function () {
        console.info('beforeEach');
        mPreferences = await data_preferences.getPreferencesSync(context, NAME);
    })

    afterEach(async function () {
        console.info('afterEach');
        await data_preferences.deletePreferences(context, NAME);
    })

    afterAll(function () {
        console.info('afterAll')
    })

    /**
     * @tc.name put StringArray sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0131
     * @tc.desc put StringArray sync interface test
     */
    it('testPreferencesPutStringArray0131', 0, function () {
        const stringArr = ['1', '2', '3'];
        mPreferences.putSync(KEY_TEST_STRING_ARRAY_ELEMENT, stringArr);
        let rc = mPreferences.getSync(KEY_TEST_STRING_ARRAY_ELEMENT, ['123', '321']);
        for (let i = 0; i < stringArr.length; i++) {
            expect(stringArr[i]).assertEqual(rc[i]);
        }
    });

    /**
     * @tc.name put NumberArray sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0132
     * @tc.desc put NumberArray sync interface test
     */
    it('testPreferencesPutNumberArray0132', 0, function () {
        const numberArr = [11, 22, 33, 44, 55];
        mPreferences.putSync(KEY_TEST_NUMBER_ARRAY_ELEMENT, numberArr);
        let rc = mPreferences.getSync(KEY_TEST_NUMBER_ARRAY_ELEMENT, [123, 321]);
        for (let i = 0; i < numberArr.length; i++) {
            expect(numberArr[i]).assertEqual(rc[i]);
        }
    });

    /**
     * @tc.name put BoolArray sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0133
     * @tc.desc put BoolArray sync interface test
     */
    it('testPreferencesPutBoolArray0133', 0, function () {
        const boolArr = [true, true, false];
        mPreferences.putSync(KEY_TEST_BOOL_ARRAY_ELEMENT, boolArr);
        let rc = mPreferences.getSync(KEY_TEST_BOOL_ARRAY_ELEMENT, [false, true]);
        for (let i = 0; i < boolArr.length; i++) {
            expect(boolArr[i]).assertEqual(rc[i]);
        }
    });

    /**
     * @tc.name getAll sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0133
     * @tc.desc getAll sync interface test
     */
    it('testPreferencesGetAll0001', 0, function () {
        const doubleArr = [11, 22, 33];
        const stringArr = ['11', '22', '33'];
        const boolArr = [true, false, false, true];
        mPreferences.putSync(KEY_TEST_STRING_ARRAY_ELEMENT, stringArr);
        mPreferences.putSync(KEY_TEST_BOOL_ARRAY_ELEMENT, boolArr);
        mPreferences.putSync(KEY_TEST_NUMBER_ARRAY_ELEMENT, doubleArr);
        mPreferences.putSync(KEY_TEST_BOOLEAN_ELEMENT, false);
        mPreferences.putSync(KEY_TEST_STRING_ELEMENT, "123");
        mPreferences.putSync(KEY_TEST_FLOAT_ELEMENT, 123.1);
        let obj = mPreferences.getAllSync();
        expect(false).assertEqual(obj.key_test_boolean)
        expect("123").assertEqual(obj.key_test_string)
        expect(123.1).assertEqual(obj.key_test_float)
        let sArr = obj.key_test_string_array
        for (let i = 0; i < sArr.length; i++) {
            expect(sArr[i]).assertEqual(stringArr[i]);
        }
        let bArr = obj.key_test_bool_array
        for (let i = 0; i < bArr.length; i++) {
            expect(bArr[i]).assertEqual(boolArr[i]);
        }
        let nArr = obj.key_test_number_array
        for (let i = 0; i < nArr.length; i++) {
            expect(nArr[i]).assertEqual(doubleArr[i]);
        }
    })

    /**
     * @tc.name clear sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Promise_0010
     * @tc.desc clear sync interface test
     */
    it('testPreferencesClear0011', 0, function () {
        mPreferences.putSync(KEY_TEST_STRING_ELEMENT, "test");
        mPreferences.flush();
        mPreferences.clearSync();
        let per = mPreferences.getSync(KEY_TEST_STRING_ELEMENT, "defaultvalue");
        expect("defaultvalue").assertEqual(per);
    })

    /**
     * @tc.name has string interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0020
     * @tc.desc has string interface test
     */
    it('testPreferencesHasKey0031', 0, function () {
        mPreferences.putSync(KEY_TEST_STRING_ELEMENT, "test");
        const ret = mPreferences.hasSync(KEY_TEST_STRING_ELEMENT);
        expect(true).assertEqual(ret);
    })

    /**
     * @tc.name has int interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0140
     * @tc.desc has int interface test
     */
    it('testPreferencesHasKey0032', 0, function () {
        mPreferences.putSync(KEY_TEST_INT_ELEMENT, 1);
        const ret = mPreferences.hasSync(KEY_TEST_INT_ELEMENT);
        expect(true).assertEqual(ret);
    })

    /**
     * @tc.name has float interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0150
     * @tc.desc has float interface test
     */
    it('testPreferencesHasKey0033', 0, function () {
        mPreferences.putSync(KEY_TEST_FLOAT_ELEMENT, 2.0);
        const ret = mPreferences.hasSync(KEY_TEST_FLOAT_ELEMENT);
        expect(true).assertEqual(ret);
    })

    /**
     * @tc.name has boolean interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0160
     * @tc.desc has boolean interface test
     */
    it('testPreferencesHasKey0034', 0, function () {
        mPreferences.putSync(KEY_TEST_BOOLEAN_ELEMENT, false);
        const ret = mPreferences.hasSync(KEY_TEST_BOOLEAN_ELEMENT);
        expect(true).assertEqual(ret);
    })

    /**
     * @tc.name has long interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0170
     * @tc.desc has long interface test
     */
    it('testPreferencesHasKey0035', 0, function () {
        mPreferences.putSync(KEY_TEST_LONG_ELEMENT, 0);
        const ret = mPreferences.hasSync(KEY_TEST_LONG_ELEMENT);
        expect(true).assertEqual(ret);
    })

    /**
     * @tc.name get string sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0030
     * @tc.desc get string sync interface test
     */
    it('testPreferencesGetDefValue0061', 0, function () {
        const ret = mPreferences.getSync(KEY_TEST_STRING_ELEMENT, "defaultValue");
        expect('defaultValue').assertEqual(ret);
    })

    /**
     * @tc.name get float sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0040
     * @tc.desc get float sync interface test
     */
    it('testPreferencesGetFloat0071', 0, function () {
        mPreferences.putSync(KEY_TEST_FLOAT_ELEMENT, 3.0);
        const ret = mPreferences.getSync(KEY_TEST_FLOAT_ELEMENT, 0.0);
        expect(3.0).assertEqual(ret);
    })

    /**
     * @tc.name get int sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0050
     * @tc.desc get int sync interface test
     */
    it('testPreferencesGetInt0081', 0,  function () {
        mPreferences.putSync(KEY_TEST_INT_ELEMENT, 3);
        const ret = mPreferences.getSync(KEY_TEST_INT_ELEMENT, 0.0);
        expect(3).assertEqual(ret);
    })

    /**
     * @tc.name get long sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0060
     * @tc.desc get long sync interface test
     */
    it('testPreferencesGetLong0091', 0, function () {
        mPreferences.putSync(KEY_TEST_LONG_ELEMENT, 3);
        const ret = mPreferences.getSync(KEY_TEST_LONG_ELEMENT, 0);
        expect(3).assertEqual(ret);
    })

    /**
     * @tc.name get String sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0070
     * @tc.desc get String sync interface test
     */
    it('tesPreferencesGetString101', 0, async function () {
        mPreferences.putSync(KEY_TEST_STRING_ELEMENT, "test");
        await mPreferences.flush();
        const ret = mPreferences.getSync(KEY_TEST_STRING_ELEMENT, "defaultvalue");
        expect('test').assertEqual(ret);
    })

    /**
     * @tc.name put boolean sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0090
     * @tc.desc put boolean sync interface test
     */
    it('testPreferencesPutBoolean0121', 0, async function () {
        mPreferences.putSync(KEY_TEST_BOOLEAN_ELEMENT, true);
        let per = mPreferences.getSync(KEY_TEST_BOOLEAN_ELEMENT, false);
        expect(true).assertEqual(per);
        await mPreferences.flush();
        data_preferences.removePreferencesFromCacheSync(context, NAME);
        mPreferences = null;
        mPreferences = data_preferences.getPreferencesSync(context, NAME);
        let per2 = mPreferences.getSync(KEY_TEST_BOOLEAN_ELEMENT, false);
        expect(true).assertEqual(per2);
    })

    /**
     * @tc.name put float sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0100
     * @tc.desc put float sync interface test
     */
    it('testPreferencesPutFloat0131', 0, async function () {
        mPreferences.putSync(KEY_TEST_FLOAT_ELEMENT, 4.0);
        let per = mPreferences.getSync(KEY_TEST_FLOAT_ELEMENT, 0.0);
        expect(4.0).assertEqual(per);
        await mPreferences.flush();
        data_preferences.removePreferencesFromCacheSync(context, NAME);
        mPreferences = null;
        mPreferences = data_preferences.getPreferencesSync(context, NAME);
        let per2 = mPreferences.getSync(KEY_TEST_FLOAT_ELEMENT, 0.0);
        expect(4.0).assertEqual(per2);
    })

    /**
     * @tc.name put int sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0110
     * @tc.desc put int sync interface test
     */
    it('testPreferencesPutInt0141', 0, async function () {
        mPreferences.putSync(KEY_TEST_INT_ELEMENT, 4);
        let per = mPreferences.getSync(KEY_TEST_INT_ELEMENT, 0);
        expect(4).assertEqual(per);
        await mPreferences.flush();
        data_preferences.removePreferencesFromCacheSync(context, NAME);
        mPreferences = null;
        mPreferences = data_preferences.getPreferencesSync(context, NAME);
        let per2 = mPreferences.getSync(KEY_TEST_INT_ELEMENT, 0);
        expect(4).assertEqual(per2);

    })

    /**
     * @tc.name put long sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0120
     * @tc.desc put long sync interface test
     */
    it('testPreferencesPutLong0151', 0, async function () {
        mPreferences.putSync(KEY_TEST_LONG_ELEMENT, 4);
        let per = mPreferences.getSync(KEY_TEST_LONG_ELEMENT, 0);
        expect(4).assertEqual(per);
        await mPreferences.flush();
        data_preferences.removePreferencesFromCacheSync(context, NAME);
        mPreferences = null;
        mPreferences = data_preferences.getPreferencesSync(context, NAME);
        let per2 = mPreferences.getSync(KEY_TEST_LONG_ELEMENT, 0);
        expect(4).assertEqual(per2);
        
    })

    /**
     * @tc.name put String sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0130
     * @tc.desc put String sync interface test
     */
    it('testPreferencesPutString0161', 0, async function () {
        mPreferences.putSync(KEY_TEST_STRING_ELEMENT, '');
        let per = mPreferences.getSync(KEY_TEST_STRING_ELEMENT, "defaultvalue");
        expect('').assertEqual(per);
        await mPreferences.flush();
        data_preferences.removePreferencesFromCacheSync(context, NAME);
        mPreferences = null;
        mPreferences = data_preferences.getPreferencesSync(context, NAME);
        let per2 = mPreferences.getSync(KEY_TEST_STRING_ELEMENT, "defaultvalue");
        expect('').assertEqual(per2);
    })

    /**
     * @tc.name put BigInt sync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0007
     * @tc.desc put BigInt sync interface test
     */
    it('testPreferencesPutBigInt0162', 0, async function () {
        let bigint = BigInt(Number.MIN_SAFE_INTEGER);
        mPreferences.putSync(KEY_TEST_BIGINT, bigint);
        let pre = mPreferences.getSync(KEY_TEST_BIGINT, BigInt(0));
        expect(bigint === pre).assertTrue();
        await mPreferences.flush();
        await data_preferences.removePreferencesFromCacheSync(context, NAME);
        mPreferences = null;
        mPreferences = await data_preferences.getPreferencesSync(context, NAME);
        let pre2 = await mPreferences.getSync(KEY_TEST_BIGINT, BigInt(0));
        expect(bigint === pre2).assertTrue();
    })
})