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
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import data_preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import featureAbility from '@ohos.ability.featureAbility';

const NAME = 'test_preferences';
const KEY_TEST_INT_ELEMENT = 'key_test_int';
const KEY_TEST_LONG_ELEMENT = 'key_test_long';
const KEY_TEST_FLOAT_ELEMENT = 'key_test_float';
const KEY_TEST_BOOLEAN_ELEMENT = 'key_test_boolean';
const KEY_TEST_STRING_ELEMENT = 'key_test_string';
const KEY_TEST_NUMBER_ARRAY_ELEMENT = 'key_test_number_array';
const KEY_TEST_STRING_ARRAY_ELEMENT = 'key_test_string_array';
const KEY_TEST_BOOL_ARRAY_ELEMENT = 'key_test_bool_array';
const KEY_TEST_UINT8ARRAY = 'key_test_uint8array';
const KEY_TEST_OBJECT = 'key_test_object';
const KEY_TEST_BIGINT = 'key_test_bigint';
var mPreferences;
var context;

describe('PreferencesPromiseJsunit', function () {
    beforeAll(function () {
        console.info('beforeAll');
        context = featureAbility.getContext();
    })

    beforeEach(async function () {
        console.info('beforeEach');
        mPreferences = await data_preferences.getPreferences(context, NAME);
    })

    afterEach(async function () {
        console.info('afterEach');
        await data_preferences.deletePreferences(context, NAME);
    })

    afterAll(function () {
        console.info('afterAll')
    })

    /**
     * @tc.name put StringArray promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0131
     * @tc.desc put StringArray promise interface test
     */
    it('testPreferencesPutStringArray0131', 0, async function () {
        var stringArr = ['1', '2', '3']
        await mPreferences.put(KEY_TEST_STRING_ARRAY_ELEMENT, stringArr);
        let pre = await mPreferences.get(KEY_TEST_STRING_ARRAY_ELEMENT, ['123', '321']);
        for (let i = 0; i < stringArr.length; i++) {
            expect(stringArr[i]).assertEqual(pre[i]);
        }
    });

    /**
     * @tc.name put NumberArray promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0132
     * @tc.desc put NumberArray promise interface test
     */
    it('testPreferencesPutNumberArray0132', 0, async function () {
        var numberArr = [11, 22, 33, 44, 55]
        await mPreferences.put(KEY_TEST_NUMBER_ARRAY_ELEMENT, numberArr);
        let pre = await mPreferences.get(KEY_TEST_NUMBER_ARRAY_ELEMENT, [123, 321]);
        for (let i = 0; i < numberArr.length; i++) {
            expect(numberArr[i]).assertEqual(pre[i]);
        }
    });

    /**
     * @tc.name put BoolArray promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0133
     * @tc.desc put BoolArray promise interface test
     */
    it('testPreferencesPutBoolArray0133', 0, async function () {
        var boolArr = [true, true, false]
        await mPreferences.put(KEY_TEST_BOOL_ARRAY_ELEMENT, boolArr);
        let pre = await mPreferences.get(KEY_TEST_BOOL_ARRAY_ELEMENT, [false, true]);
        for (let i = 0; i < boolArr.length; i++) {
            expect(boolArr[i]).assertEqual(pre[i]);
        }
    });

    /**
     * @tc.name getAll promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0133
     * @tc.desc getAll promise interface test
     */
    it('testPreferencesGetAll0001', 0, async function () {
        let doubleArr = [11, 22, 33]
        let stringArr = ['11', '22', '33']
        let boolArr = [true, false, false, true]
        await mPreferences.put(KEY_TEST_STRING_ARRAY_ELEMENT, stringArr)
        await mPreferences.put(KEY_TEST_BOOL_ARRAY_ELEMENT, boolArr)
        await mPreferences.put(KEY_TEST_NUMBER_ARRAY_ELEMENT, doubleArr)
        await mPreferences.put(KEY_TEST_BOOLEAN_ELEMENT, false)
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, "123")
        await mPreferences.put(KEY_TEST_FLOAT_ELEMENT, 123.1)
        let promise = mPreferences.getAll()
        await promise.then((obj) => {
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
        }).catch((err) => {
            expect(null).assertFail();
        })
    })

    /**
     * @tc.name clear promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Promise_0010
     * @tc.desc clear promise interface test
     */
    it('testPreferencesClear0011', 0, async function (done) {
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, "test");
        await mPreferences.flush();
        const promise = mPreferences.clear();
        await promise.then(async (ret) => {
            let per = await mPreferences.get(KEY_TEST_STRING_ELEMENT, "defaultvalue");
            done();
            expect("defaultvalue").assertEqual(per);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name has string interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0020
     * @tc.desc has string interface test
     */
    it('testPreferencesHasKey0031', 0, async function () {
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, "test");
        const promise = mPreferences.has(KEY_TEST_STRING_ELEMENT);
        await promise.then((ret) => {
            expect(true).assertEqual(ret);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name has int interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0140
     * @tc.desc has int interface test
     */
    it('testPreferencesHasKey0032', 0, async function () {
        await mPreferences.put(KEY_TEST_INT_ELEMENT, 1);
        const promise = mPreferences.has(KEY_TEST_INT_ELEMENT);
        await promise.then((ret) => {
            expect(true).assertEqual(ret);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name has float interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0150
     * @tc.desc has float interface test
     */
    it('testPreferencesHasKey0033', 0, async function () {
        await mPreferences.put(KEY_TEST_FLOAT_ELEMENT, 2.0);
        const promise = mPreferences.has(KEY_TEST_FLOAT_ELEMENT);
        await promise.then((ret) => {
            expect(true).assertEqual(ret);
        }).catch((err) => {
            expect(null).assertFail();
        }); 
    })

    /**
     * @tc.name has boolean interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0160
     * @tc.desc has boolean interface test
     */
    it('testPreferencesHasKey0034', 0, async function () {
        await mPreferences.put(KEY_TEST_BOOLEAN_ELEMENT, false);
        const promise = mPreferences.has(KEY_TEST_BOOLEAN_ELEMENT);
        await promise.then((ret) => {
            expect(true).assertEqual(ret);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name has long interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0170
     * @tc.desc has long interface test
     */
    it('testPreferencesHasKey0035', 0, async function () {
        await mPreferences.put(KEY_TEST_LONG_ELEMENT, 0);
        const promise = mPreferences.has(KEY_TEST_LONG_ELEMENT);
        await promise.then((ret) => {
            expect(true).assertEqual(ret);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name get string promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0030
     * @tc.desc get string promise interface test
     */
    it('testPreferencesGetDefValue0061', 0, async function () {
        const promise = mPreferences.get(KEY_TEST_STRING_ELEMENT, "defaultValue");
        await promise.then((ret) => {
            expect('defaultValue').assertEqual(ret);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name get float promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0040
     * @tc.desc get float promise interface test
     */
    it('testPreferencesGetFloat0071', 0, async function () {
        await mPreferences.put(KEY_TEST_FLOAT_ELEMENT, 3.0);
        const promise = mPreferences.get(KEY_TEST_FLOAT_ELEMENT, 0.0);
        await promise.then((ret) => {
            expect(3.0).assertEqual(ret);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name get int promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0050
     * @tc.desc get int promise interface test
     */
    it('testPreferencesGetInt0081', 0, async function () {
        await mPreferences.put(KEY_TEST_INT_ELEMENT, 3);
        const promise = mPreferences.get(KEY_TEST_INT_ELEMENT, 0.0);
        await promise.then((ret) => {
            expect(3).assertEqual(ret);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name get long promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0060
     * @tc.desc get long promise interface test
     */
    it('testPreferencesGetLong0091', 0, async function () {
        await mPreferences.put(KEY_TEST_LONG_ELEMENT, 3);
        const promise = mPreferences.get(KEY_TEST_LONG_ELEMENT, 0);
        await promise.then((ret) => {
            expect(3).assertEqual(ret);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name get String promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0070
     * @tc.desc get String promise interface test
     */
    it('tesPreferencesGetString101', 0, async function () {
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, "test");
        const promise = mPreferences.get(KEY_TEST_STRING_ELEMENT, "defaultvalue");
        await promise.then((ret) => {
            expect('test').assertEqual(ret);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name get Uint8Array promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0080
     * @tc.desc get Uint8Array promise interface test
     */
    it('tesPreferencesGetUint8Array102', 0, async function () {
        let uInt8Array = new util.TextEncoder().encodeInto("π\\n\\b@.(){},");
        await mPreferences.put(KEY_TEST_UINT8ARRAY, uInt8Array);
        const promise = mPreferences.get(KEY_TEST_UINT8ARRAY, new Uint8Array(0));
        await promise.then((ret) => {
            expect(uInt8Array.toString() === ret.toString()).assertTrue();
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name put boolean promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0090
     * @tc.desc put boolean promise interface test
     */
    it('testPreferencesPutBoolean0121', 0, async function (done) {
        const promise = mPreferences.put(KEY_TEST_BOOLEAN_ELEMENT, true);
        await promise.then(async (ret) => {
            let per = await mPreferences.get(KEY_TEST_BOOLEAN_ELEMENT, false);
            expect(true).assertEqual(per);
            await mPreferences.flush();
            await data_preferences.removePreferencesFromCache(context, NAME);
            mPreferences = null;
            mPreferences = await data_preferences.getPreferences(context, NAME);
            let per2 = await mPreferences.get(KEY_TEST_BOOLEAN_ELEMENT, false);
            done();
            expect(true).assertEqual(per2);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name put float promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0100
     * @tc.desc put float promise interface test
     */
    it('testPreferencesPutFloat0131', 0, async function (done) {
        const promise = mPreferences.put(KEY_TEST_FLOAT_ELEMENT, 4.0);
        await promise.then(async (ret) => {
            let per = await mPreferences.get(KEY_TEST_FLOAT_ELEMENT, 0.0);
            expect(4.0).assertEqual(per);
            await mPreferences.flush();
            await data_preferences.removePreferencesFromCache(context, NAME);
            mPreferences = null;
            mPreferences = await data_preferences.getPreferences(context, NAME);
            let per2 = await mPreferences.get(KEY_TEST_FLOAT_ELEMENT, 0.0);
            done();
            expect(4.0).assertEqual(per2);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name put int promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0110
     * @tc.desc put int promise interface test
     */
    it('testPreferencesPutInt0141', 0, async function () {
        const promise = mPreferences.put(KEY_TEST_INT_ELEMENT, 4);
        await promise.then(async (ret) => {
            let per = await mPreferences.get(KEY_TEST_INT_ELEMENT, 0);
            expect(4).assertEqual(per);
            await mPreferences.flush();
            await data_preferences.removePreferencesFromCache(context, NAME);
            mPreferences = null;
            mPreferences = await data_preferences.getPreferences(context, NAME);
            let per2 = await mPreferences.get(KEY_TEST_INT_ELEMENT, 0);
            expect(4).assertEqual(per2);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name put long promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0120
     * @tc.desc put long promise interface test
     */
    it('testPreferencesPutLong0151', 0, async function () {
        const promise = mPreferences.put(KEY_TEST_LONG_ELEMENT, 4);
        await promise.then(async (ret) => {
            let per = await mPreferences.get(KEY_TEST_LONG_ELEMENT, 0);
            expect(4).assertEqual(per);
            await mPreferences.flush();
            await data_preferences.removePreferencesFromCache(context, NAME);
            mPreferences = null;
            mPreferences = await data_preferences.getPreferences(context, NAME);
            let per2 = await mPreferences.get(KEY_TEST_LONG_ELEMENT, 0);
            expect(4).assertEqual(per2);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name put String promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0130
     * @tc.desc put String promise interface test
     */
    it('testPreferencesPutString0161', 0, async function (done) {
        const promise = mPreferences.put(KEY_TEST_STRING_ELEMENT, '');
        await promise.then(async (ret) => {
            let per = await mPreferences.get(KEY_TEST_STRING_ELEMENT, "defaultvalue")
            expect('').assertEqual(per);
            await mPreferences.flush();
            await data_preferences.removePreferencesFromCache(context, NAME);
            mPreferences = null;
            mPreferences = await data_preferences.getPreferences(context, NAME);
            let per2 = await mPreferences.get(KEY_TEST_STRING_ELEMENT, "defaultvalue")
            done();
            expect('').assertEqual(per2);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name get empty array promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0131
     * @tc.desc get empty array promise interface test
     */
    it('testPreferencesGetEmptyArray0171', 0, function (done) {
        let defaultValue = new Array();
        let data = mPreferences.get("mytest", defaultValue);
        data.then((value) => {
            expect(value).assertEqual(defaultValue);
            done();
        }).catch((err)=> {
            expect(null).assertFail();
            done();
        })
    })

    /**
     * @tc.name get empty array promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0132
     * @tc.desc get empty array promise interface test
     */
    it('testPreferencesFlushEmptyArray0181', 0, async function () { 
        let value = new Array();
        const promise = mPreferences.put(KEY_TEST_NUMBER_ARRAY_ELEMENT, value);
        await promise.then(async (ret) => {
            let pre = await mPreferences.get(KEY_TEST_NUMBER_ARRAY_ELEMENT, "defaultvalue");
            expect(pre instanceof Array).assertEqual(true);
            expect(pre.length).assertEqual(0);
            await mPreferences.flush(); 
            await data_preferences.removePreferencesFromCache(context, NAME);
            mPreferences = null;
            mPreferences = await data_preferences.getPreferences(context, NAME);
            let pre2 = await mPreferences.get(KEY_TEST_NUMBER_ARRAY_ELEMENT, "defaultvalue")
            expect(pre2 instanceof Array).assertEqual(true);
            expect(pre2.length).assertEqual(0);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name get empty array promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0132
     * @tc.desc get empty array promise interface test
     */
    it('testPreferencesGetEmptyArray0191', 0, async function () {
        const promise = mPreferences.put(KEY_TEST_NUMBER_ARRAY_ELEMENT, []);
        await promise.then(async (ret) => {
            let pre = await mPreferences.get(KEY_TEST_NUMBER_ARRAY_ELEMENT, "defaultvalue");
            expect(pre instanceof Array).assertEqual(true);
            expect(pre.length).assertEqual(0);
            await mPreferences.flush(); 
            await data_preferences.removePreferencesFromCache(context, NAME);
            mPreferences = null;
            mPreferences = await data_preferences.getPreferences(context, NAME);
            let pre2 = await mPreferences.get(KEY_TEST_NUMBER_ARRAY_ELEMENT, "defaultvalue")
            expect(pre2 instanceof Array).assertEqual(true);
            expect(pre2.length).assertEqual(0);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name put Uint8Array promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0201
     * @tc.desc put Uint8Array promise interface test
     */
    it('testPreferencesPutUint8Array0201', 0, async function () {
        let uInt8Array = new util.TextEncoder().encodeInto("abc@#$%123");
        const promise = mPreferences.put(KEY_TEST_UINT8ARRAY, uInt8Array);
        await promise.then(async (ret) => {
            let pre = await mPreferences.get(KEY_TEST_UINT8ARRAY, new Uint8Array(0));
            expect(uInt8Array.toString() === pre.toString()).assertTrue();
            await mPreferences.flush();
            await data_preferences.removePreferencesFromCache(context, NAME);
            mPreferences = null;
            mPreferences = await data_preferences.getPreferences(context, NAME);
            let pre2 = await mPreferences.get(KEY_TEST_UINT8ARRAY, new Uint8Array(0));
            expect(uInt8Array.toString() === pre2.toString()).assertTrue();
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name put Uint8Array promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0202
     * @tc.desc put Uint8Array promise interface test
     */
    it('testPreferencesPutUint8Array0202', 0, async function () {
        let uInt8Array = new Uint8Array(8192);
        uInt8Array.fill(100);
        const promise = mPreferences.put(KEY_TEST_UINT8ARRAY, uInt8Array);
        await promise.then(async (ret) => {
            let pre = await mPreferences.get(KEY_TEST_UINT8ARRAY, new Uint8Array(0));
            expect(uInt8Array.toString() === pre.toString()).assertTrue();
            await mPreferences.flush();
            await data_preferences.removePreferencesFromCache(context, NAME);
            mPreferences = null;
            mPreferences = await data_preferences.getPreferences(context, NAME);
            let pre2 = await mPreferences.get(KEY_TEST_UINT8ARRAY, new Uint8Array(0));
            expect(uInt8Array.toString() === pre2.toString()).assertTrue();
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name put Uint8Array promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0203
     * @tc.desc put Uint8Array promise interface test
     */
    it('testPreferencesPutUint8Array0203', 0, async function () {
        let uInt8Array = new Uint8Array(8193);
        uInt8Array.fill(100);
        try {
            await mPreferences.put(KEY_TEST_UINT8ARRAY, uInt8Array);
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code + ", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
        }
    })

    /**
     * @tc.name put Uint8Array promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0204
     * @tc.desc put object promise interface test
     */
    it('testPreferencesPutObject001', 0, async function () {
        let obj = {
            name: "xiaowang",
            age: 18
        }
        try {
            await mPreferences.put(KEY_TEST_OBJECT, obj);
            let res = await mPreferences.get(KEY_TEST_OBJECT, {});
            console.log('get object data : ' + JSON.stringify(res));
            expect(obj["age"]).assertEqual(18);
            expect(JSON.stringify(res)).assertEqual(JSON.stringify(obj));
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code + ", message =" + err.message);
            expect(null).assertFail();
        }
    })

    /**
     * @tc.name put Uint8Array promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0205
     * @tc.desc put object promise interface test
     */
    it('testPreferencesPutObject002', 0, async function (done) {
        let obj = {
            name: "xiaohong",
            age: "99"
        }
        const promise = mPreferences.put(KEY_TEST_OBJECT, obj);
        await promise.then(async (ret) => {
            await mPreferences.flush();
            let data = await mPreferences.get(KEY_TEST_OBJECT, {});
            expect(JSON.stringify(data)).assertEqual(JSON.stringify(obj));
            console.log('get object data : ' + JSON.stringify(data));

            await data_preferences.removePreferencesFromCache(context, NAME);
            mPreferences = null;
            mPreferences = await data_preferences.getPreferences(context, NAME);
            let data2 = await mPreferences.get(KEY_TEST_OBJECT, {});
            console.log('get object data2 : ' + JSON.stringify(data2));
            expect(obj["age"]).assertEqual("99");
            expect(JSON.stringify(data2)).assertEqual(JSON.stringify(obj));
            done();
        }).catch((err) => {
            console.log("try catch err =" + err + ", code =" + err.code + ", message =" + err.message);
            expect(null).assertFail();

        });
    })

    /**
     * @tc.name put BigInt promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0206
     * @tc.desc put Bigint negative test
     */
    it('testPreferencesPutBigInt0001', 0, async function () {
        let bigint = BigInt("-12345678912345678912345678971234567123456");
        await mPreferences.put(KEY_TEST_BIGINT, bigint);
        let pre = await mPreferences.get(KEY_TEST_BIGINT, BigInt(0));
        expect(bigint === pre).assertTrue();
        await mPreferences.flush();
        await data_preferences.removePreferencesFromCache(context, NAME);
        mPreferences = null;
        mPreferences = await data_preferences.getPreferences(context, NAME);
        let pre2 = await mPreferences.get(KEY_TEST_BIGINT, BigInt(0));
        expect(bigint === pre2).assertTrue();
    })

    /**
     * @tc.name put BigInt promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0207
     * @tc.desc put Bigint positive test
     */
    it('testPreferencesPutBigInt0002', 0, async function () {
        let bigint = BigInt("12345678912345678912345678971234567123456");
        await mPreferences.put(KEY_TEST_BIGINT, bigint);
        let pre = await mPreferences.get(KEY_TEST_BIGINT, BigInt(0));
        expect(bigint === pre).assertTrue();
        await mPreferences.flush();
        await data_preferences.removePreferencesFromCache(context, NAME);
        mPreferences = null;
        mPreferences = await data_preferences.getPreferences(context, NAME);
        let pre2 = await mPreferences.get(KEY_TEST_BIGINT, BigInt(0));
        expect(bigint === pre2).assertTrue();
    })

    /**
     * @tc.name put BigInt promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0208
     * @tc.desc put Bigint boundary value test
     */
    it('testPreferencesPutBigInt0003', 0, async function () {
        let bigint = BigInt(Number.MAX_SAFE_INTEGER);
        await mPreferences.put(KEY_TEST_BIGINT, bigint);
        let pre = await mPreferences.get(KEY_TEST_BIGINT, BigInt(0));
        expect(bigint === pre).assertTrue();
        await mPreferences.flush();
        await data_preferences.removePreferencesFromCache(context, NAME);
        mPreferences = null;
        mPreferences = await data_preferences.getPreferences(context, NAME);
        let pre2 = await mPreferences.get(KEY_TEST_BIGINT, BigInt(0));
        expect(bigint === pre2).assertTrue();
    })

    /**
     * @tc.name put BigInt promise interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_0209
     * @tc.desc put Bigint boundary value test
     */
    it('testPreferencesPutBigInt0004', 0, async function () {
        let bigint = BigInt(Number.MIN_SAFE_INTEGER);
        await mPreferences.put(KEY_TEST_BIGINT, bigint);
        let pre = await mPreferences.get(KEY_TEST_BIGINT, BigInt(0));
        expect(bigint === pre).assertTrue();
        await mPreferences.flush();
        await data_preferences.removePreferencesFromCache(context, NAME);
        mPreferences = null;
        mPreferences = await data_preferences.getPreferences(context, NAME);
        let pre2 = await mPreferences.get(KEY_TEST_BIGINT, BigInt(0));
        expect(bigint === pre2).assertTrue();
    })
})