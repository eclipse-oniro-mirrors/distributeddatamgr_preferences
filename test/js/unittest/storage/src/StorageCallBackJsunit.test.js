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
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import storage from '@ohos.data.storage'

const PATH = "/data/storage/el2/database/test_storage";
const KEY_TEST_INT_ELEMENT = 'key_test_int';
const KEY_TEST_LONG_ELEMENT = 'key_test_long';
const KEY_TEST_FLOAT_ELEMENT = 'key_test_float';
const KEY_TEST_BOOLEAN_ELEMENT = 'key_test_boolean';
const KEY_TEST_STRING_ELEMENT = 'key_test_string';
var mPref;

describe('StorageCallBackJsunit', function () {
    beforeAll(function () {
        console.info('beforeAll')
    })

    beforeEach( function () {
        console.info('beforeEach');
        mPref = storage.getStorageSync(PATH);
    })

    afterEach(function () {
        console.info('afterEach');
        storage.deleteStorageSync(PATH);
    })

    afterAll(function () {
        console.info('afterAll')
    })

    /**
     * @tc.name clear callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0010
     * @tc.desc clear callback interface test
     */
    it('testClear0012', 0, function (done) {
        mPref.putSync(KEY_TEST_STRING_ELEMENT, "test");
        mPref.flushSync();
        mPref.clear(function (err, ret) {
            expect("defaultvalue").assertEqual(mPref.getSync(KEY_TEST_STRING_ELEMENT, "defaultvalue"));
            done();
        });
    })

    /**
     * @tc.name has string callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0020
     * @tc.desc has string callback interface test
     */
    it('testHasKey0032', 0, function (done) {
        mPref.putSync(KEY_TEST_STRING_ELEMENT, "test");
        mPref.has(KEY_TEST_STRING_ELEMENT, function (err, ret) {
            expect(true).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name has int callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0130
     * @tc.desc has int callback interface test
     */
    it('testHasKey0033', 0, function (done) {
        mPref.putSync(KEY_TEST_INT_ELEMENT, 1);
        mPref.has(KEY_TEST_INT_ELEMENT, function (err, ret) {
            expect(true).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name has float callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0140
     * @tc.desc has float callback interface test
     */
    it('testHasKey0034', 0, function (done) {
        mPref.putSync(KEY_TEST_FLOAT_ELEMENT, 1.1);
        mPref.has(KEY_TEST_FLOAT_ELEMENT, function (err, ret) {
            expect(true).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name has long callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0150
     * @tc.desc has long callback interface test
     */
    it('testHasKey0035', 0, function (done) {
        mPref.putSync(KEY_TEST_LONG_ELEMENT, 0);
        mPref.has(KEY_TEST_LONG_ELEMENT, function (err, ret) {
            expect(true).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name has boolean callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0160
     * @tc.desc has boolean callback interface test
     */
    it('testHasKey0036', 0, function (done) {
        mPref.putSync(KEY_TEST_BOOLEAN_ELEMENT, false);
        mPref.has(KEY_TEST_BOOLEAN_ELEMENT, function (err, ret) {
            expect(true).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name get defaultValue callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0030
     * @tc.desc get defaultValue callback interface test
     */
    it('testGetDefValue0062', 0, function (done) {
        mPref.get(KEY_TEST_STRING_ELEMENT, "defaultValue", function (err, ret) {
            expect('defaultValue').assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name get float callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0040
     * @tc.desc get float callback interface test
     */
    it('testGetFloat0072', 0, function (done) {
        mPref.putSync(KEY_TEST_FLOAT_ELEMENT, 3.0);
        mPref.get(KEY_TEST_FLOAT_ELEMENT, 0.0, function (err, ret) {
            expect(3.0).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name get int callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0050
     * @tc.desc get int callback interface test
     */
    it('testGetInt0082', 0, function (done) {
        mPref.putSync(KEY_TEST_INT_ELEMENT, 3);
        mPref.get(KEY_TEST_INT_ELEMENT, 0.0, function (err, ret) {
            expect(3).assertEqual(ret);
            done();
        })
    })

    /**
     * @tc.name get long callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0060
     * @tc.desc get long callback interface test
     */
    it('testGetLong0092', 0, function (done) {
        mPref.putSync(KEY_TEST_LONG_ELEMENT, 3);
        expect(3).assertEqual(mPref.getSync(KEY_TEST_LONG_ELEMENT, 0));
        mPref.get(KEY_TEST_LONG_ELEMENT, 0, function (err, ret) {
            expect(3).assertEqual(ret);
            done();
        });
    })

    /**
     * @tc.name get String callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0070
     * @tc.desc get String callback interface test
     */
    it('testGetString102', 0, function (done) {
        mPref.putSync(KEY_TEST_STRING_ELEMENT, "test");
        mPref.flushSync();
        mPref.get(KEY_TEST_STRING_ELEMENT, "defaultvalue", function (err, ret) {
            expect('test').assertEqual(ret);
            done();
        });
    })

    /**
     * @tc.name put boolean callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0080
     * @tc.desc put boolean callback interface test
     */
    it('testPutBoolean0122', 0, function (done) {
        mPref.put(KEY_TEST_BOOLEAN_ELEMENT, true, function (err, ret) {
            expect(true).assertEqual(mPref.getSync(KEY_TEST_BOOLEAN_ELEMENT, false));
            mPref.flushSync();
            storage.removeStorageFromCacheSync(PATH);
            mPref = null;
            mPref = storage.getStorageSync(PATH);
            expect(true).assertEqual(mPref.getSync(KEY_TEST_BOOLEAN_ELEMENT, false));
            done();
        });
    })

    /**
     * @tc.name put float callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0090
     * @tc.desc put float callback interface test
     */
    it('testPutFloat0132', 0, function (done) {
        mPref.put(KEY_TEST_FLOAT_ELEMENT, 4.0, function (err, ret) {
            expect(4.0).assertEqual(mPref.getSync(KEY_TEST_FLOAT_ELEMENT, 0.0));
            mPref.flushSync();
            storage.removeStorageFromCache(PATH);
            mPref = null;
            mPref = storage.getStorageSync(PATH);
            expect(4.0).assertEqual(mPref.getSync(KEY_TEST_FLOAT_ELEMENT, 0.0));
            done();
        });
    })

    /**
     * @tc.name put int callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0100
     * @tc.desc put int callback interface test
     */
    it('testPutInt0142', 0, function (done) {
        mPref.put(KEY_TEST_INT_ELEMENT, 4,  function (err, ret) {
            expect(4).assertEqual(mPref.getSync(KEY_TEST_INT_ELEMENT, 0));
            mPref.flushSync();
            storage.removeStorageFromCache(PATH);
            mPref = null;
            mPref = storage.getStorageSync(PATH);
            expect(4).assertEqual(mPref.getSync(KEY_TEST_INT_ELEMENT, 0));
            done();
        });
    })

    /**
     * @tc.name put long callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0110
     * @tc.desc put long callback interface test
     */
    it('testPutLong0152', 0, function (done) {
        mPref.putSync(KEY_TEST_LONG_ELEMENT, 4);
        mPref.put(KEY_TEST_LONG_ELEMENT, 4, function (err, ret) {
            expect(4).assertEqual(mPref.getSync(KEY_TEST_LONG_ELEMENT, 0));
            mPref.flushSync();
            storage.removeStorageFromCacheSync(PATH);
            mPref = null;
            mPref = storage.getStorageSync(PATH);
            expect(4).assertEqual(mPref.getSync(KEY_TEST_LONG_ELEMENT, 0));
            done();
        });
    })

    /**
     * @tc.name put String callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0120
     * @tc.desc put String callback interface test
     */
    it('testPutString0162', 0, function (done) {
        mPref.put(KEY_TEST_STRING_ELEMENT, '', function (err, ret) {
            expect('').assertEqual(mPref.getSync(KEY_TEST_STRING_ELEMENT, "defaultvalue"));
            mPref.flushSync();
            storage.removeStorageFromCacheSync(PATH);
            mPref = null;
            mPref = storage.getStorageSync(PATH);
            expect('').assertEqual(mPref.getSync(KEY_TEST_STRING_ELEMENT, "defaultvalue"));
            done();
        });
    })

    /**
     * @tc.name clear、put、get、flush String callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0120
     * @tc.desc flush String callback interface test
     */
     it('testCallback0172', 0, function (done) {
        console.log("*******************testCallback0172 begin.");
        mPref.clear(function (err, val) {
            if(err){
                console.log("*******************clear error: " + err);
                expect(false).assertTrue();
            }
            mPref.put(KEY_TEST_STRING_ELEMENT, '', function (err, ret) {
                if(err){
                    console.log("*******************put error: " + err);
                    expect(false).assertTrue();
                }
                console.log("*******************put done.");
                mPref.get(KEY_TEST_STRING_ELEMENT, "defaultvalue", function (err, pre) {
                    if(err){
                        console.log("*******************get error: " + err);
                        expect(false).assertTrue();
                    }
                    expect('').assertEqual(pre);
                    mPref.flush(function (err, val) {
                        if(err){
                            console.log("*******************flush error: " + err);
                            expect(false).assertTrue();
                        }
                        mPref.get(KEY_TEST_STRING_ELEMENT, "defaultvalue", function (err, pre2) {
                            if(err){
                                console.log("*******************get error: " + err);
                                expect(false).assertTrue();
                            }
                            expect('').assertEqual(pre2);
                            done();
                            console.log("*******************testCallback0172 end.");
                        })
                    });
                })
            });
        });
    })

    /**
     * @tc.name test put interface
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0121
     * @tc.desc test put interface input parameter is illegal.
     */
    it('testPutIllegal001', 0, async function (done) {
        let illegalKey = false;
        let legalValue = "test";
        try {
            mPref.put(illegalKey, legalValue, (ret) => {
                done();
            });
            expect(false).assertTrue();
        } catch (err) {
            console.log("try catch err =" + err);
            done();
        }
    })

    /**
     * @tc.name test put interface
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0122
     * @tc.desc test put interface input parameter is illegal.
     */
    it('testPutIllegal002', 0, async function (done) {
        let illegalKey = 123;
        let legalValue = "test";
        try {
            mPref.put(illegalKey, legalValue, (ret) => {
                done();
            });
            expect(false).assertTrue();
        } catch (err) {
            console.log("try catch err =" + err);
            done();
        }
    })

    /**
     * @tc.name test put interface
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0123
     * @tc.desc test put interface input parameter value exceed 8192byte.
     */
    it('testPutIllegal003', 0, async function (done) {
        let phoneStr = "1";
        phoneStr = phoneStr.repeat(8193);
        try {
            mPref.put("phoneNum", phoneStr, (ret) => {
                done();
            });
            expect(false).assertTrue();
        } catch (err) {
            console.log("try catch err =" + err);
            done();
        }
    })

    /**
     * @tc.name test put interface
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0124
     * @tc.desc test put interface input parameter value is legal.
     */
    it('testPutIllegal004', 0, async function (done) {
        let phoneStr = "1";
        phoneStr = phoneStr.repeat(8192);
        try {
            mPref.put("phoneNum", phoneStr, (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err);
            expect(false).assertTrue();
            done();
        }
    })

    /**
     * @tc.name test put interface
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0125
     * @tc.desc test put interface input parameter key exceed 80byte.
     */
    it('testPutIllegal005', 0, async function (done) {
        let phoneNum = "1";
        phoneNum = phoneNum.repeat(81);
        try {
            mPref.put(phoneNum, "123456", (ret) => {
                done();
            });
            expect(false).assertTrue();
        } catch (err) {
            console.log("try catch err =" + err);
            done();
        }
    })

    /**
     * @tc.name test put interface
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0126
     * @tc.desc test put interface input parameter key is legal.
     */
    it('testPutIllegal006', 0, async function (done) {
        let phoneNum = "1";
        phoneNum = phoneNum.repeat(80);
        try {
            mPref.put(phoneNum, "123456", (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err);
            expect(false).assertTrue();
            done();
        }
    })

    /**
     * @tc.name test get interface
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0127
     * @tc.desc test get interface input parameter is illegal.
     */
    it('testGetIllegal001', 0, async function (done) {
        let illegalKey = 123;
        try {
            mPref.get(illegalKey, "defaultValue", (ret) => {
                done();
            });
            expect(false).assertTrue();
        } catch (err) {
            console.log("try catch err =" + err);
            done();
        }
    })

    /**
     * @tc.name test get interface
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0127
     * @tc.desc test get interface input parameter is illegal.
     */
    it('testGetIllegal002', 0, async function (done) {
        let illegalKey = true;
        try {
            mPref.get(illegalKey, "defaultValue", (ret) => {
                done();
            });
            expect(false).assertTrue();
        } catch (err) {
            console.log("try catch err =" + err);
            done();
        }
    })

    /**
     * @tc.name test get interface
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0128
     * @tc.desc test get interface input parameter key exceed 80byte.
     */
    it('testGetIllegal003', 0, async function (done) {
        let illegalKey = "1";
        illegalKey = illegalKey.repeat(81);
        try {
            mPref.get(illegalKey, "defaultValue", (ret) => {
                done();
            });
            expect(false).assertTrue();
        } catch (err) {
            console.log("try catch err =" + err);
            done();
        }
    })

    /**
     * @tc.name test get interface
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0129
     * @tc.desc test get interface input parameter key is legal.
     */
    it('testGetIllegal004', 0, async function (done) {
        let legalKey = "1";
        legalKey = legalKey.repeat(80);
        try {
            mPref.get(legalKey, "defaultValue", (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err);
            expect(false).assertTrue();
            done();
        }
    })
})