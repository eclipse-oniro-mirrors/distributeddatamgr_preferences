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
import data_preferences from '@ohos.data.preferences'
import featureAbility from '@ohos.ability.featureAbility'

const NAME = 'v9_test_preferences_promise'
const KEY_TEST_INT_ELEMENT = 'key_test_int'
const KEY_TEST_LONG_ELEMENT = 'key_test_long'
const KEY_TEST_FLOAT_ELEMENT = 'key_test_float'
const KEY_TEST_BOOLEAN_ELEMENT = 'key_test_boolean'
const KEY_TEST_STRING_ELEMENT = 'key_test_string'
const KEY_TEST_NUMBER_ARRAY_ELEMENT = 'key_test_number_array'
const KEY_TEST_STRING_ARRAY_ELEMENT = 'key_test_string_array'
const KEY_TEST_BOOL_ARRAY_ELEMENT = 'key_test_bool_array'
var mPreference
var context

describe('_preferencesTest', async function () {
    beforeAll(async function () {
        console.info('beforeAll')
        context = featureAbility.getContext()
        mPreference = await data_preferences.getPreferences(context, NAME)
    })

    afterAll(async function () {
        console.info('afterAll')
        await data_preferences.deletePreferences(context, NAME)
    })

    beforeEach(async function () {
        console.info('beforeEach')
        await mPreference.clear();
        await mPreference.flush();
    })

    it('testPreferencesPromise001', 0, function (done) {
        console.log("testPreferencesPromise001 begin.")
        try{
            if(mPreference== undefined) {
                console.log("mPreference undefined")
                expect(false).assertTrue()
            }
            mPreference.clear().then(()=>{                    
                mPreference.put(KEY_TEST_STRING_ELEMENT, '123').then((ret)=>{
                    mPreference.get(KEY_TEST_STRING_ELEMENT, "defaultvalue").then((pre)=>{
                        expect('123').assertEqual(pre)
                        mPreference.flush().then(()=>{
                            data_preferences.removePreferencesFromCache(context, NAME).then(()=>{
                                mPreference.get(KEY_TEST_STRING_ELEMENT, "defaultvalue").then((pre2)=>{
                                    expect('123').assertEqual(pre2)
                                    done()
                                    console.log("testPreferencesPromise001 end.")
                                }).catch((err) => {
                                    console.log("get err =" + err + ", code =" + err.code +", message =" + err.message)
                                    expect(false).assertTrue()
                                })
                            }).catch((err) => {
                                console.log("removePreferencesFromCache err =" + err + ", code =" + err.code +", message =" + err.message)
                                expect(false).assertTrue()
                            })
                        }).catch((err) => {
                            console.log("flush err =" + err + ", code =" + err.code +", message =" + err.message)
                            expect(false).assertTrue()
                        })
                    }).catch((err) => {
                        console.log("get err =" + err + ", code =" + err.code +", message =" + err.message)
                        expect(false).assertTrue()
                    })
                }).catch((err) => {
                    console.log("put err =" + err + ", code =" + err.code +", message =" + err.message)
                    expect(false).assertTrue()
                })
            }).catch((err) => {
                console.log("clear err =" + err + ", code =" + err.code +", message =" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            expect(false).assertTrue()
        }
    })
    
    //get error parsers
    it('testPreferencesPromise002', 0, function (done) {
        console.log("testPreferencesPromise002 begin.")
        try{
            mPreference.get(1233).then((ret)=>{
                console.log("get err")
                expect(false).assertTrue()
            }).catch((err) => {
                console.log("get err =" + err + ", code =" + err.code +", message =" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            done()
            console.log("testPreferencesPromise002 end.")
        }
    })

    //get OK parsers
    it('testPreferencesPromise003', 0, async function (done) {
        console.log("testPreferencesPromise003 begin.")
        try{
            await mPreference.put(KEY_TEST_STRING_ELEMENT, '123');
            mPreference.get(KEY_TEST_STRING_ELEMENT, KEY_TEST_INT_ELEMENT).then((ret) => {
                done()
                expect('123').assertEqual(ret)
                console.log("testPreferencesPromise003 end.")
            }).catch((err) => {
                console.log("get err =" + err + ", code =" + err.code +", message =" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            expect(false).assertTrue()
        }
    })

    //getAll 
    it('testPreferencesPromise004', 0, function (done) {
        console.log("testPreferencesPromise004 begin.")
        try {
            mPreference.getAll().then((ret) => {
                done()
                console.log("testPreferencesPromise004 end.")
            }).catch((err) => {
                console.log("getAll err =" + err + ", code =" + err.code + ", message =" + err.message)
                expect(false).assertTrue()
            })
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect(false).assertTrue()
        }
    })

    //has error parsers
    it('testPreferencesPromise005', 0, function (done) {
        console.log("testPreferencesPromise005 begin.")
        try{
            mPreference.has(123).then((val)=>{
                console.log("has err")
                expect(false).assertTrue()
            }).catch((err) => {
                console.log("has err =" + err + ", code =" + err.code +", message =" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            done()
            console.log("testPreferencesPromise005 end.")
        }
    })

    //has OK parsers
    it('testPreferencesPromise006', 0, function (done) {
        console.log("testPreferencesPromise006 begin.")
        try{
            mPreference.has(KEY_TEST_STRING_ELEMENT).then((val)=>{
                done()
                console.log("testPreferencesPromise006 end.")
            }).catch((err) => {
                console.log("has err =" + err + ", code =" + err.code +", message =" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            expect(false).assertTrue()
        }
    })

    //put error parsers
    it('testPreferencesPromise007', 0, function (done) {
        console.log("testPreferencesPromise007 begin.")
        try{
            mPreference.put(1233).then(()=>{
                console.log("put err")
                expect(false).assertTrue()
            }).catch((err) => {
                console.log("put err =" + err + ", code =" + err.code +", message =" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            done()
            console.log("testPreferencesPromise007 end.")
        }
    })

    //put OK parsers
    it('testPreferencesPromise008', 0, function (done) {
        console.log("testPreferencesPromise008 begin.")
        try{
            mPreference.put(KEY_TEST_STRING_ELEMENT, KEY_TEST_INT_ELEMENT).then(()=>{
                done()
                console.log("testPreferencesPromise008 end.")
            }).catch((err) => {
                console.log("put err =" + err + ", code =" + err.code +", message =" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            expect(false).assertTrue()
        }
    })

    //delete error parsers
    it('testPreferencesPromise009', 0, function (done) {
        console.log("testPreferencesPromise009 begin.")
        try{
            mPreference.delete(1233).then(()=>{
                console.log("delete err")
                expect(false).assertTrue()
            }).catch((err) => {
                console.log("delete err =" + err + ", code =" + err.code +", message =" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            done()
            console.log("testPreferencesPromise009 end.")
        }
    })

    //delete OK parsers
    it('testPreferencesPromise010', 0, function (done) {
        console.log("testPreferencesPromise010 begin.")
        try{
            mPreference.delete(KEY_TEST_STRING_ELEMENT).then(()=>{
                done()
                console.log("testPreferencesPromise005 end.")
            }).catch((err) => {
                console.log("delete err =" + err + ", code =" + err.code +", message =" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            expect(false).assertTrue()
        }
    })

    //clear
    it('testPreferencesPromise011', 0, function (done) {
        console.log("testPreferencesPromise011 begin.")
        try{
            mPreference.clear().then(()=>{
                done()
                console.log("testPreferencesPromise011 end.")
            }).catch((err) => {
                console.log("clear err =" + err + ", code =" + err.code +", message =" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("trycatch err =" + err + ", code =" + err.code +", message =" + err.message)
            expect(false).assertTrue()
        }
    })

    //flush OK parsers
    it('testPreferencesPromise012', 0, function (done) {
        console.log("testPreferencesPromise012 begin.")
        try {
            mPreference.flush().then(() => {
                done()
                console.log("testPreferencesPromise012 end.")
            }).catch((err) => {
                console.log("flush err =" + err + ", code =" + err.code + ", message =" + err.message)
                expect(false).assertTrue()
            })
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect(false).assertTrue()
        }
    })

    //on OK parsers
    it('testPreferencesPromise014', 0, async function (done) {
        console.log("testPreferencesPromise014 begin.")
        await mPreference.clear();
        try {
            var observer = function (key) {
                console.info('testPreferencesPromise014 key' + key);
                done();
                expect(KEY_TEST_STRING_ELEMENT).assertEqual(key);
            };
            mPreference.on('change', observer);
            await mPreference.put(KEY_TEST_STRING_ELEMENT, "abc");
            await mPreference.flush();
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect(false).assertTrue()
        } finally {
            mPreference.off('change', observer);
        }
    })

    //on err parsers
    it('testPreferencesPromise015', 0, async function (done) {
        console.log("testPreferencesPromise015 begin.")
        await mPreference.clear();
        try {
            var observer = function (key) {
                console.info('testPreferencesPromise015 key' + key);
                expect(KEY_TEST_STRING_ELEMENT).assertEqual(key);
            };
            mPreference.on('sschange', observer);
            expect(false).assertTrue()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            done();
        }
    })

    //off OK parsers
    it('testPreferencesPromise016', 0, async function (done) {
        console.log("testPreferencesPromise016 begin.")
        try {
            var observer = function (key) {
                console.info('testPreferencesPromise016 key' + key);
                expect(false).assertTrue()
            };
            mPreference.on('change', observer);
            mPreference.off('change', observer);
            await mPreference.put(KEY_TEST_STRING_ELEMENT, "abb");
            await mPreference.flush();
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect(false).assertTrue()
        }
        done();
    })

    //off err parsers
    it('testPreferencesPromise017', 0, async function (done) {
        console.log("testPreferencesPromise017 begin.")
        try {
            var observer = function (key) {
                console.info('testPreferencesPromise017 key' + key);
                expect(KEY_TEST_STRING_ELEMENT).assertEqual(key);
            };
            mPreference.on('change', observer);
            mPreference.off('sschange', observer);
            expect(false).assertTrue()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            done();
        }
    })
})