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

describe('V9_PreferencesPromiseJsunit', async function () {
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
        } finally {
            mPreference.off('change', observer);
        }
    })

    it('testPreferencesDataChange001', 0, async function (done) {
        console.log("testPreferencesDataChange001 begin.")
        await mPreference.clear();
        try {
            var observer = function (data) {
            };
            mPreference.on('dataChange', [], observer);
            expect(false).assertTrue()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            done();
        }
    })

    it('testPreferencesDataChange002', 0, async function (done) {
        console.log("testPreferencesDataChange002 begin.")
        await mPreference.clear();
        try {
            var observer = function (data) {}
            mPreference.off('dataChange', {}, observer);
            expect(false).assertTrue()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            done();
        }
    })

    it('testPreferencesDataChange003', 0, async function (done) {
        console.log("testPreferencesDataChange003 begin.")
        await mPreference.clear();
        let obj = {
            "key":"value"
        }
        try {
            var observer = function (data) {
            };
            mPreference.on('dataChange', obj, observer);
            expect(false).assertTrue()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            done();
        }
    })

    it('testPreferencesDataChange004', 0, async function (done) {
        console.log("testPreferencesDataChange004 begin.")
        await mPreference.clear();
        try {
            mPreference.on('dataChange', []);
            expect(false).assertTrue()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            done();
        }
    })

    it('testPreferencesDataChange005', 0, async function (done) {
        console.log("testPreferencesDataChange005 begin.")
        await mPreference.clear();
        try {
            let obj1 = {
                "key1":"value1"
            }
            let obj2 = {
                "key1":"value1",
                "key2":222
            }
            var observer1 = function (data) {
                for (const key in data)  {
                    if (data.hasOwnProperty(key)) {
                        console.log(`ob1 Key: ${key}, Value: ${data[key]}`)
                        if (data[key] != obj1[key]) {
                            console.log(`Not as expected act: ${data[key]}, exc: ${obj1[key]}`)
                        }
                    }
                }
                expect(Object.keys(data).length).assertEqual(Object.keys(obj1).length)
                expect(JSON.stringify(data)).assertEqual(JSON.stringify(obj1))
            }
            var observer2 = function (data) {
                for (const key in data)  {
                    if (data.hasOwnProperty(key)) {
                        console.log(`ob2 Key: ${key}, Value: ${data[key]}`)
                        if (data[key] != obj2[key]) {
                            console.log(`Not as expected act: ${data[key]}, exc: ${obj2[key]}`)
                        }
                    }
                }
                expect(Object.keys(data).length).assertEqual(Object.keys(obj2).length)
                expect(JSON.stringify(data)).assertEqual(JSON.stringify(obj2))
            }
            mPreference.on('dataChange', ['key1'], observer1);
            mPreference.on('dataChange', ['key1', 'key2', 'key3'], observer2);
            await mPreference.put("key2", "value2")
            await mPreference.put("key1", "value1")
            await mPreference.put("key2", 222)
            await mPreference.flush()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect(false).assertTrue()
        } finally {
            mPreference.off('dataChange', ['key1'], observer1)
            mPreference.off('dataChange', ['key1', 'key2', 'key4'], observer2)
            mPreference.off('dataChange', ['key2', 'key3'], observer2)
            done()
        }
    })

    it('testPreferencesDataChange006', 0, async function (done) {
        console.log("testPreferencesDataChange006 begin.")
        await mPreference.clear();
        try {
            var observer1 = function (data) {
                console.log("observer1")
                expect(false).assertTrue()
            }
            var observer2 = function (data) {
                console.log("observer2")
            }
            var observer3= function (data) {
                console.log("observer3")
            }
            let keys = ['key1', 'key2', 'key3']
            mPreference.on('dataChange', keys, observer1);
            mPreference.on('dataChange', keys, observer2);
            mPreference.on('dataChange', keys, observer3);
            mPreference.off('dataChange', [], observer1)
            await mPreference.put("key2", "value2")
            await mPreference.put("key1", "value1")
            await mPreference.flush()
            mPreference.off('dataChange', [])
            done()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect(false).assertTrue()
        }
    })

    it('testPreferencesDataChange007', 0, async function (done) {
        console.log("testPreferencesDataChange007 begin.")
        await mPreference.clear();
        try {
            let obj = {
                "key2":"value2"
            }
            var observer1 = function (data) {
                console.log("observer1")
                expect(Object.keys(data).length).assertEqual(Object.keys(obj).length)
                expect(JSON.stringify(data)).assertEqual(JSON.stringify(obj))
            }
            var observer2 = function (data) {
                console.log("observer2")
                expect(Object.keys(data).length).assertEqual(Object.keys(obj).length)
                expect(JSON.stringify(data)).assertEqual(JSON.stringify(obj))
            }
            let keys = ['key1', 'key2', 'key3']
            mPreference.on('dataChange', keys, observer1);
            mPreference.on('dataChange', keys, observer2);
            await mPreference.put("key1", "value1")
            await mPreference.put("key2", "value2")
            await mPreference.put("key3", "value3")
            mPreference.off('dataChange', ['key1', 'key3'])
            await mPreference.flush()
            mPreference.off('dataChange', [])
            done()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect(false).assertTrue()
        }
    })



    it('testPreferencesDataChange008', 0, async function (done) {
        console.log("testPreferencesDataChange008 begin.")
        await mPreference.clear();
        try {
            var observer1 = function (data) {
                console.log("observer1")
                expect(false).assertTrue()
            }
            var observer2 = function (data) {
                console.log("observer2")
                expect(false).assertTrue()
            }
            var observer3= function (data) {
                console.log("observer3")
                expect(false).assertTrue()
            }
            let keys = ['key1', 'key2', 'key3']
            mPreference.on('dataChange', keys, observer1);
            mPreference.on('dataChange', keys, observer2);
            mPreference.on('dataChange', keys, observer3);
            mPreference.off('dataChange', [])
            await mPreference.put("key2", "value2")
            await mPreference.put("key1", "value1")
            await mPreference.flush()
            done()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect(false).assertTrue()
        }
    })

    it('testPreferencesDataChange009', 0, async function (done) {
        console.log("testPreferencesDataChange009 begin.")
        await mPreference.clear();
        try {
            let obj1 = {
                "key2":"value2"
            }
            var observer1 = function (data) {
                console.log("observer1")
                expect(JSON.stringify(data)).assertEqual(JSON.stringify(obj1))
            }
            var observer2 = function (data) {
                console.log("observer2")
                expect(false).assertTrue()
            }
            mPreference.on('dataChange', ['key1', 'key2'], observer1);
            mPreference.on('dataChange', ['key1', 'key3'], observer2);
            await mPreference.put("key2", "value2")
            await mPreference.put("key1", "value1")
            await mPreference.put("key3", "value3")
            mPreference.off('dataChange', ['key1', 'key3'], observer1);
            mPreference.off('dataChange', ['key1', 'key3'], observer2);
            await mPreference.flush()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect(false).assertTrue()
        } finally {
            mPreference.off('dataChange', [])
            done()
        }
    })

    it('testPreferencesDataChange010', 0, async function (done) {
        console.log("testPreferencesDataChange010 begin.")
        await mPreference.clear();
        try {
            let obj1 = {
                "key1":"value1",
                "key2":null
            }
            var observer1 = function (data) {
                for (const key in data)  {
                    if (data.hasOwnProperty(key)) {
                        console.log(`ob1 Key: ${key}, Value: ${data[key]}`)
                        if (data[key] != obj1[key]) {
                            console.log(`Not as expected act: ${data[key]}, exc: ${obj1[key]}`)
                        }
                    }
                }
                expect(Object.keys(data).length).assertEqual(Object.keys(obj1).length)
                expect(JSON.stringify(data)).assertEqual(JSON.stringify(obj1))
            }
            mPreference.on('dataChange', ['key1', 'key2'], observer1);
            await mPreference.put("key2", 222)
            await mPreference.put("key1", "value1")
            await mPreference.delete("key2", (err) => {
                if (err) {
                    console.log("delete err =" + err + ", code =" + err.code +", message =" + err.message)
                    expect(false).assertTrue()
                }
                console.log("delete err")
            });
            await mPreference.flush()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect(false).assertTrue()
        } finally {
            mPreference.off('dataChange', [])
            done()
        }
    })
})