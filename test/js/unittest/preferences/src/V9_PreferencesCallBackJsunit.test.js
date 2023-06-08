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
import data_preferences from '@ohos.data.preferences'
import featureAbility from '@ohos.ability.featureAbility'

const NAME = 'v9_test_preferences_callback'
const KEY_TEST_INT_ELEMENT = 'key_test_int'
const KEY_TEST_LONG_ELEMENT = 'key_test_long'
const KEY_TEST_FLOAT_ELEMENT = 'key_test_float'
const KEY_TEST_BOOLEAN_ELEMENT = 'key_test_boolean'
const KEY_TEST_STRING_ELEMENT = 'key_test_string'
const KEY_TEST_NUMBER_ARRAY_ELEMENT = 'key_test_number_array'
const KEY_TEST_STRING_ARRAY_ELEMENT = 'key_test_string_array'
const KEY_TEST_BOOL_ARRAY_ELEMENT = 'key_test_bool_array'
var mPreference = undefined
var context

const ILLEGAL_CHAR_10 = '1234567890'
const ILLEGAL_CHAR_80 = ILLEGAL_CHAR_10.repeat(8);
const ILLEGAL_CHAR_81 = ILLEGAL_CHAR_80 + '1';
const ILLEGAL_CHAR_8192 = ILLEGAL_CHAR_80.repeat(102) + '1'.repeat(32);
const ILLEGAL_CHAR_8193 = ILLEGAL_CHAR_8192 + '1';

describe('V9_PreferencesCallBackJsunit', async function () {
    beforeAll(async function () {
        console.info('beforeAll')
        context = featureAbility.getContext()
        mPreference = await data_preferences.getPreferences(context, NAME)
    })

    afterAll(async function () {
        console.info('afterAll')
        await data_preferences.deletePreferences(context, NAME)
    })

     /**
     * @tc.name has、delete、get、flush String callback interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_CallBack_0120
     * @tc.desc flush String callback interface test
     */

    it('testPreferencesCallback001', 0, function (done) {
        console.log("testPreferencesCallback001 begin.")
        try{
            mPreference.clear(function (err, val) {
                if(err){
                    console.log("clear err =" + err + ", code =" + err.code +", message =" + err.message)
                    expect(false).assertTrue()
                }
                mPreference.put(KEY_TEST_STRING_ELEMENT, 'abc', function (err, ret) {
                    if(err){
                        console.log("put err =" + err + ", code =" + err.code +", message =" + err.message)
                        expect(false).assertTrue()
                    }
                    mPreference.get(KEY_TEST_STRING_ELEMENT, "defaultvalue", function (err, pre) {
                        if(err){
                            console.log("get err =" + err + ", code =" + err.code +", message =" + err.message)
                            expect(false).assertTrue()
                        }
                        expect('abc').assertEqual(pre)
                        mPreference.flush(function (err, val) {
                            if(err){
                                console.log("flush err =" + err + ", code =" + err.code +", message =" + err.message)
                                expect(false).assertTrue()
                            }
                            data_preferences.removePreferencesFromCache(context, NAME,(err)=>{
                                if(err){
                                    console.log("removePreferencesFromCache err =" + err + ", code =" + err.code +", message =" + err.message)
                                    expect(false).assertTrue()
                                }
                                mPreference.get(KEY_TEST_STRING_ELEMENT, "defaultvalue", function (err, pre2) {
                                    if(err){
                                        console.log("get err =" + err + ", code =" + err.code +", message =" + err.message)
                                        expect(false).assertTrue()
                                    }
                                    expect('abc').assertEqual(pre2)
                                    done()
                                    console.log("testPreferencesCallback001 end.")
                                })
                            })
                        })
                    })
                })
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            expect(false).assertTrue()
        }
    })
    
    // get err parsers
    it('testPreferencesCallback002', 0, function (done) {
        console.log("testPreferencesCallback002 begin.")
        try {
            mPreference.get(123, function (err, val) {
                if (err) {
                    console.log("get err =" + err + ", code =" + err.code + ", message =" + err.message)
                    expect(false).assertTrue()
                }
                expect(true).assertEqual(val)
            })
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            done()
            console.log("testPreferencesCallback002 end.")
        }
    })
    
    // get OK parsers
    it('testPreferencesCallback003', 0, function (done) {
        console.log("testPreferencesCallback003 begin.")
        try {
            mPreference.get(KEY_TEST_STRING_ELEMENT, KEY_TEST_INT_ELEMENT, function (err, val) {
                if (err) {
                    console.log("get err =" + err + ", code =" + err.code + ", message =" + err.message)
                    expect(false).assertTrue()
                }
                expect('abc').assertEqual(val)
                done()
                console.log("testPreferencesCallback003 end.")
            })
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect(false).assertTrue()
        }
    })

    // getAll
    it('testPreferencesCallback004', 0, function (done) {
        console.log("testPreferencesCallback004 begin.")
        try {
            mPreference.getAll(function (err, val) {
                if (err) {
                    console.log("getAll err =" + err + ", code =" + err.code + ", message =" + err.message)
                    expect(false).assertTrue()
                }
                console.log("getAll val = " + JSON.stringify(val))
                done()
                console.log("testPreferencesCallback004 end.")
            })
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect(false).assertTrue()
        }
        done()
    })

    // has Error parsers
    it('testPreferencesCallback005', 0, function (done) {
        console.log("testPreferencesCallback005 begin.")
        try{
            mPreference.has(123,function (err, val) {
                console.log("has err")
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            done()
            console.log("testPreferencesCallback005 end.")
        }
    })

    // has OK parsers
    it('testPreferencesCallback006', 0, function (done) {
        console.log("testPreferencesCallback006 begin.")
        try{
            mPreference.has(KEY_TEST_STRING_ELEMENT, function (err, val) {
                if (err) {
                    console.log("has err =" + err + ", code =" + err.code +", message =" + err.message)
                    expect(false).assertTrue()
                }
                expect(true).assertEqual(val)
                done()
                console.log("testPreferencesCallback006 end.")
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            expect(false).assertTrue()
        }
    })
    
    // put Error parsers
    it('testPreferencesCallback007', 0, function (done) {
        console.log("testPreferencesCallback007 begin.")
        try{
            mPreference.put(123, function (err) {
                console.log("put err")
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            done()
            console.log("testPreferencesCallback007 end.")
        }
    })

    // put OK parsers
    it('testPreferencesCallback008', 0, function (done) {
        console.log("testPreferencesCallback008 begin.")
        try{
            mPreference.put(KEY_TEST_STRING_ELEMENT, KEY_TEST_INT_ELEMENT, function (err) {
                if (err) {
                    console.log("put err =" + err + ", code =" + err.code +", message =" + err.message)
                    expect(false).assertTrue()
                }
                done()
                console.log("testPreferencesCallback008 end.")
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            expect(false).assertTrue()
        }
    })

    //delete Error parsers
    it('testPreferencesCallback009', 0, function (done) {
        console.log("testPreferencesCallback009 begin.")
        try{
            mPreference.delete(1233, function(err) {
                if (err) {
                    console.log("delete err =" + err + ", code =" + err.code +", message =" + err.message)
                    expect(false).assertTrue()
                }
                console.log("delete err")
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            done()
            console.log("testPreferencesCallback009 end.")
        }
    })

    //delete OK parsers
    it('testPreferencesCallback010', 0, function (done) {
        console.log("testPreferencesCallback010 begin.")
        try{
            mPreference.delete(KEY_TEST_STRING_ELEMENT, function(err) {
                if (err) {
                    console.log("delete err =" + err + ", code =" + err.code +", message =" + err.message)
                    expect(false).assertTrue()
                }
                done()
                console.log("testPreferencesCallback010 end.")
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            expect(false).assertTrue()
        }
    })

    // clear
    it('testPreferencesCallback011', 0, function (done) {
        console.log("testPreferencesCallback011 begin.")
        try{
            mPreference.clear(function (err) {
                if (err) {
                    console.log("clear err =" + err + ", code =" + err.code +", message =" + err.message)
                    expect(false).assertTrue()
                }
                done()
                console.log("testPreferencesCallback011 end.")
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            expect(false).assertTrue()
        }
    })
        
    // flush
    it('testPreferencesCallback012', 0, function (done) {
        console.log("testPreferencesCallback012 begin.")
        try{
            mPreference.flush(function (err) {
                if (err) {
                    console.log("flush err =" + err + ", code =" + err.code +", message =" + err.message)
                    expect(false).assertTrue()
                }
                done()
                console.log("testPreferencesCallback012 end.")
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            expect(false).assertTrue()
        }
    })

    /**
     * @tc.name test put interface
     * @tc.desc test put interface input parameter is illegal.
     */
    it('testPreferencesPutIllegal0001', 0, async function (done) {
        let illegalKey = 123;
        let legalValue = "test";
        try {
            mPreference.put(illegalKey, legalValue, (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
            done();
        }
    })

    /**
     * @tc.name test put interface
     * @tc.desc test put interface input parameter is illegal.
     */
    it('testPreferencesPutIllegal0002', 0, async function (done) {
        let illegalKey = true;
        let legalValue = "test";
        try {
            mPreference.put(illegalKey, legalValue, (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
            done();
        }
    })

    /**
     * @tc.name test put interface
     * @tc.desc test put interface input parameter key exceed 80bytes.
     */
    it('testPreferencesPutIllegal0003', 0, async function (done) {
        try {
            mPreference.put(ILLEGAL_CHAR_81, "123456", (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
            done();
        }
    })

    /**
     * @tc.name test put interface
     * @tc.desc test put interface input parameter key is legal.
     */
    it('testPreferencesPutIllegal0004', 0, async function (done) {
        try {
            mPreference.put(ILLEGAL_CHAR_80, "123456", (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect(false).assertEqual(true);
            done();
        }
    })

    /**
     * @tc.name test put interface
     * @tc.desc test put interface input parameter value exceed 8192bytes.
     */
    it('testPreferencesPutIllegal0005', 0, async function (done) {
        try {
            mPreference.put("test", ILLEGAL_CHAR_8193, (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
            done();
        }
    })

    /**
     * @tc.name test put interface
     * @tc.desc test put interface input parameter value is legal.
     */
    it('testPreferencesPutIllegal0006', 0, async function (done) {
        try {
            mPreference.put("test", ILLEGAL_CHAR_8192, (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect(false).assertEqual(true);
            done();
        }
    })

    /**
     * @tc.name test get interface
     * @tc.desc test get interface input parameter is illegal.
     */
    it('testPreferencesGetIllegal0001', 0, async function (done) {
        let illegalKey = true;
        try {
            mPreference.get(illegalKey, "defaultValue", (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
            done();
        }
    })

    /**
     * @tc.name test get interface
     * @tc.desc test get interface input parameter is illegal.
     */
    it('testPreferencesGetIllegal0002', 0, async function (done) {
        let illegalKey = 123;
        try {
            mPreference.get(illegalKey, "defaultValue", (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
            done();
        }
    })

    /**
     * @tc.name test get interface
     * @tc.desc test get interface input parameter key exceed 80bytes.
     */
    it('testPreferencesGetIllegal0003', 0, async function (done) {
        try {
            mPreference.get(ILLEGAL_CHAR_81, "defaultValue", (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
            done();
        }
    })

    /**
     * @tc.name test get interface
     * @tc.desc test get interface input parameter key is legal.
     */
    it('testPreferencesGetIllegal0004', 0, async function (done) {
        try {
            mPreference.get(ILLEGAL_CHAR_80, "defaultValue", (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect(false).assertEqual(true);
            done();
        }
    })

    /**
     * @tc.name test delete interface
     * @tc.desc test delete interface input parameter is illegal.
     */
    it('testPreferencesDeleteIllegal0001', 0, async function (done) {
        let illegalKey = 123;
        try {
            mPreference.delete(illegalKey, (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
            done();
        }
    })

    /**
     * @tc.name test delete interface
     * @tc.desc test delete interface input parameter is illegal.
     */
    it('testPreferencesDeleteIllegal0002', 0, async function (done) {
        let illegalKey = false;
        try {
            mPreference.delete(illegalKey, (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
            done();
        }
    })

    /**
     * @tc.name test delete interface
     * @tc.desc test delete interface input parameter key exceed 80bytes.
     */
    it('testPreferencesDeleteIllegal0003', 0, async function (done) {
        try {
            mPreference.delete(ILLEGAL_CHAR_81, (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
            done();
        }
    })

    /**
     * @tc.name test delete interface
     * @tc.desc test delete interface input parameter key is legal.
     */
    it('testPreferencesDeleteIllegal0004', 0, async function (done) {
        try {
            mPreference.delete(ILLEGAL_CHAR_80, (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect(false).assertEqual(true);
            done();
        }
    })

    /**
     * @tc.name test has interface
     * @tc.desc test has interface input parameter is illegal.
     */
    it('testPreferencesHasIllegal0001', 0, async function (done) {
        let illegalKey = false;
        try {
            mPreference.has(illegalKey, (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
            done();
        }
    })

    /**
     * @tc.name test has interface
     * @tc.desc test has interface input parameter is illegal.
     */
    it('testPreferencesHasIllegal0002', 0, async function (done) {
        let illegalKey = 123;
        try {
            mPreference.has(illegalKey, (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
            done();
        }
    })

    /**
     * @tc.name test has interface
     * @tc.desc test has interface input parameter key exceed 80bytes.
     */
    it('testPreferencesHasIllegal0003', 0, async function (done) {
        try {
            mPreference.has(ILLEGAL_CHAR_81, (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect("401").assertEqual(err.code.toString());
            done();
        }
    })

    /**
     * @tc.name test has interface
     * @tc.desc test has interface input parameter key is legal.
     */
    it('testPreferencesHasIllegal0004', 0, async function (done) {
        try {
            mPreference.has(ILLEGAL_CHAR_80, (ret) => {
                done();
            });
        } catch (err) {
            console.log("try catch err =" + err + ", code =" + err.code +", message =" + err.message);
            expect(false).assertEqual(true);
            done();
        }
    })
})