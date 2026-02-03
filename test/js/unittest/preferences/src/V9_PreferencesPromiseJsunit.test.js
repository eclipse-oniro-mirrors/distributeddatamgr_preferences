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
            done();
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

    // test on dataChange with an empty array key
    it('testPreferencesDataChange001', 0, async function (done) {
        console.log("testPreferencesDataChange001 begin.")
        await mPreference.clear();
        try {
            var observer = function (data) {
            };
            mPreference.on('dataChange', [], observer);
            expect().assertFail()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            done();
        }
    })

    // test off dataChange with non-array key 
    it('testPreferencesDataChange002', 0, async function (done) {
        console.log("testPreferencesDataChange002 begin.")
        await mPreference.clear();
        try {
            var observer = function (data) {}
            mPreference.off('dataChange', {}, observer);
            expect().assertFail()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            done();
        }
    })

    // test on dataChange with non-array key
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
            expect().assertFail()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            done();
        }
    })

    // test on dataChange without callback
    it('testPreferencesDataChange004', 0, async function (done) {
        console.log("testPreferencesDataChange004 begin.")
        await mPreference.clear();
        try {
            mPreference.on('dataChange', []);
            expect().assertFail()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            done();
        }
    })

    // test the subscription callback of on dataChange
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
            expect().assertFail()
        } finally {
            mPreference.off('dataChange', ['key1'], observer1)
            mPreference.off('dataChange', ['key1', 'key2', 'key4'], observer2)
            mPreference.off('dataChange', ['key2', 'key3'], observer2)
            done()
        }
    })

    // test off dataChange with an empty key and callback1
    it('testPreferencesDataChange006', 0, async function (done) {
        console.log("testPreferencesDataChange006 begin.")
        await mPreference.clear();
        try {
            var observer1 = function (data) {
                console.log("observer1")
                expect().assertFail()
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
            expect().assertFail()
        }
    })

    // test off dataChange with array keys1 and without callback
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
            expect().assertFail()
        }
    })

    // test off dataChange with an empty array key without callback
    it('testPreferencesDataChange008', 0, async function (done) {
        console.log("testPreferencesDataChange008 begin.")
        await mPreference.clear();
        try {
            var observer1 = function (data) {
                console.log("observer1")
                expect().assertFail()
            }
            var observer2 = function (data) {
                console.log("observer2")
                expect().assertFail()
            }
            var observer3= function (data) {
                console.log("observer3")
                expect().assertFail()
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
            expect().assertFail()
        }
    })

    // test off dataChange with array keys1, callback1 and array keys2, callback2
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
                expect().assertFail()
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
            expect().assertFail()
        } finally {
            mPreference.off('dataChange', [])
            done()
        }
    })

    // test put then delete and on dataChange subscribe to callback
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
            await mPreference.delete("key2");
            await mPreference.flush()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect().assertFail()
        } finally {
            mPreference.off('dataChange', [])
            done()
        }
    })
    // test multiple dataChange observers with same key
    it('testPreferencesDataChange011', 0, async function (done) {
        console.log("testPreferencesDataChange011 begin.")
        await mPreference.clear();
        try {
            let callCount = 0;
            var observer1 = function (data) {
                console.log("observer1 called")
                expect("value1").assertEqual(data["testKey"])
                callCount++;
                // Check if all observers have been called
                if (callCount === 3) {
                    expect(3).assertEqual(callCount);
                    done();
                }
            }
            var observer2 = function (data) {
                console.log("observer2 called")
                expect("value1").assertEqual(data["testKey"])
                callCount++;
                if (callCount === 3) {
                    expect(3).assertEqual(callCount);
                    done();
                }
            }
            var observer3 = function (data) {
                console.log("observer3 called")
                expect("value1").assertEqual(data["testKey"])
                callCount++;
                if (callCount === 3) {
                    expect(3).assertEqual(callCount);
                    done();
                }
            }
            mPreference.on('dataChange', ['testKey'], observer1);
            mPreference.on('dataChange', ['testKey'], observer2);
            mPreference.on('dataChange', ['testKey'], observer3);
            await mPreference.put("testKey", "value1")
            await mPreference.flush()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect().assertFail()
            done()
        } finally {
            mPreference.off('dataChange', [])
        }
    })

    // test dataChange with multiple keys trigger
    it('testPreferencesDataChange012', 0, async function (done) {
        console.log("testPreferencesDataChange012 begin.")
        await mPreference.clear();
        try {
            let expectedData = {
                "key1": "value1",
                "key2": 222,
                "key3": true
            }
            var observer = function (data) {
                console.log("observer called with data: " + JSON.stringify(data))
                expect(Object.keys(data).length).assertEqual(Object.keys(expectedData).length)
                expect(JSON.stringify(data)).assertEqual(JSON.stringify(expectedData))
                done()
            }
            mPreference.on('dataChange', ['key1', 'key2', 'key3'], observer);
            await mPreference.put("key1", "value1")
            await mPreference.put("key2", 222)
            await mPreference.put("key3", true)
            await mPreference.flush()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect().assertFail()
            done()
        } finally {
            mPreference.off('dataChange', [])
        }
    })

    // test dataChange observer with no matching keys
    it('testPreferencesDataChange013', 0, async function (done) {
        console.log("testPreferencesDataChange013 begin.")
        await mPreference.clear();
        try {
            let observerCalled = false;
            var observer = function (_data) {
                console.log("observer should not be called")
                observerCalled = true;
            }
            mPreference.on('dataChange', ['key1', 'key2'], observer);
            await mPreference.put("key3", "value3")
            await mPreference.put("key4", 444)
            await mPreference.flush()
            // Wait a bit to ensure observer had time to be called if it was going to be
            setTimeout(() => {
                expect(false).assertEqual(observerCalled)
                mPreference.off('dataChange', [])
                done()
            }, 100)
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect().assertFail()
            mPreference.off('dataChange', [])
            done()
        }
    })

    // test dataChange with value type changes
    it('testPreferencesDataChange014', 0, async function (done) {
        console.log("testPreferencesDataChange014 begin.")
        await mPreference.clear();
        try {
            let testData = [
                { "stringKey": "stringValue" },
                { "numberKey": 12345 },
                { "boolKey": true },
                { "floatKey": 123.45 }
            ]
            let testIndex = 0;
            var observer = function (data) {
                console.log("observer called with data: " + JSON.stringify(data))
                if (testIndex < testData.length) {
                    expect(JSON.stringify(data)).assertEqual(JSON.stringify(testData[testIndex]))
                    testIndex++;
                    if (testIndex === testData.length) {
                        expect(testIndex).assertEqual(testData.length)
                        done()
                    }
                }
            }
            mPreference.on('dataChange', ['stringKey', 'numberKey', 'boolKey', 'floatKey'], observer);
            await mPreference.put("stringKey", "stringValue")
            await mPreference.flush()
            await mPreference.put("numberKey", 12345)
            await mPreference.flush()
            await mPreference.put("boolKey", true)
            await mPreference.flush()
            await mPreference.put("floatKey", 123.45)
            await mPreference.flush()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect().assertFail()
            done()
        } finally {
            mPreference.off('dataChange', [])
        }
    })

    // test dataChange with clear operation
    it('testPreferencesDataChange015', 0, async function (done) {
        console.log("testPreferencesDataChange015 begin.")
        await mPreference.clear();
        try {
            var observer = function (data) {
                console.log("obs called with data: " + JSON.stringify(data))
                // Verify observer receives the put operations data
                expect(3).assertEqual(Object.keys(data).length)
                expect("value1").assertEqual(data["key1"])
                expect("value2").assertEqual(data["key2"])
                expect("value3").assertEqual(data["key3"])
                mPreference.off('dataChange', [])
                done()
            }
            mPreference.on('dataChange', ['key1', 'key2', 'key3'], observer);
            await mPreference.put("key1", "value1")
            await mPreference.put("key2", "value2")
            await mPreference.put("key3", "value3")
            await mPreference.flush()
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect().assertFail()
            mPreference.off('dataChange', [])
            done()
        }
    })

    // Test 'change' observer receives correct key when multiple values change
    it('testPreferencesChangeObserver001', 0, async function (done) {
        console.log("testPreferencesChangeObserver001 begin.")
        await mPreference.clear();
        try {
            let receivedKeys = [];
            var observer = function (key) {
                console.log("change observer received key: " + key);
                receivedKeys.push(key);
                if (receivedKeys.length === 3) {
                    // Verify observer was called for each key change
                    expect(3).assertEqual(receivedKeys.length);
                    expect(true).assertEqual(receivedKeys.includes("key1"));
                    expect(true).assertEqual(receivedKeys.includes("key2"));
                    expect(true).assertEqual(receivedKeys.includes("key3"));
                    mPreference.off('change', observer);
                    done();
                }
            }
            mPreference.on('change', observer);
            await mPreference.put("key1", "value1");
            await mPreference.put("key2", "value2");
            await mPreference.put("key3", "value3");
            await mPreference.flush();
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect().assertFail()
            mPreference.off('change', observer);
            done();
        }
    })

    // Test 'change' observer can be unregistered and stops receiving notifications
    it('testPreferencesChangeObserver002', 0, async function (done) {
        console.log("testPreferencesChangeObserver002 begin.")
        await mPreference.clear();
        try {
            let callCount = 0;
            let firstFlushDone = false;
            var observer = function (key) {
                console.log("change observer received key: " + key);
                callCount++;
                if (callCount === 1 && !firstFlushDone) {
                    firstFlushDone = true;
                    expect(1).assertEqual(callCount);

                    // Unregister observer
                    mPreference.off('change', observer);

                    // Trigger another change
                    setTimeout(async () => {
                        await mPreference.put("key2", "value2");
                        await mPreference.flush();

                        // Wait to ensure observer had time to be called if it was going to be
                        setTimeout(() => {
                            // Observer should not be called again
                            expect(1).assertEqual(callCount);
                            done();
                        }, 100);
                    }, 10);
                }
            }
            mPreference.on('change', observer);
            await mPreference.put("key1", "value1");
            await mPreference.flush();
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect().assertFail()
            done();
        }
    })

    // Test 'dataChange' observer receives partial data for subscribed keys only
    it('testPreferencesDataChangeObserver001', 0, async function (done) {
        console.log("testPreferencesDataChangeObserver001 begin.")
        await mPreference.clear();
        try {
            var observer = function (data) {
                console.log("dataChange observer received: " + JSON.stringify(data));
                // Verify only subscribed keys are in the data
                expect(data !== null).assertTrue();
                expect(2).assertEqual(Object.keys(data).length);
                expect("value1").assertEqual(data["key1"]);
                expect("value3").assertEqual(data["key3"]);
                expect(undefined).assertEqual(data["key2"]);
                mPreference.off('dataChange', ['key1', 'key3'], observer);
                done();
            }
            // Subscribe to only key1 and key3
            mPreference.on('dataChange', ['key1', 'key3'], observer);

            // Modify key1, key2, and key3
            await mPreference.put("key1", "value1");
            await mPreference.put("key2", "value2");
            await mPreference.put("key3", "value3");
            await mPreference.flush();
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect().assertFail()
            mPreference.off('dataChange', ['key1', 'key3'], observer);
            done();
        }
    })

    // Test 'dataChange' observer with delete operation
    it('testPreferencesDataChangeObserver002', 0, async function (done) {
        console.log("testPreferencesDataChangeObserver002 begin.")
        await mPreference.clear();
        try {
            var observer = function (data) {
                console.log("dataChange observer received: " + JSON.stringify(data));
                // Verify delete operation is reflected
                expect(data !== null).assertTrue();
                expect(1).assertEqual(Object.keys(data).length);
                expect(null).assertEqual(data["key1"]);
                mPreference.off('dataChange', ['key1'], observer);
                done();
            }
            mPreference.on('dataChange', ['key1'], observer);

            // Put then delete the same key
            await mPreference.put("key1", "value1");
            await mPreference.delete("key1");
            await mPreference.flush();
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect().assertFail()
            mPreference.off('dataChange', ['key1'], observer);
            done();
        }
    })

    // Test 'multiProcessChange' observer can be registered
    it('testPreferencesMultiProcessChangeObserver001', 0, async function (done) {
        console.log("testPreferencesMultiProcessChangeObserver001 begin.")
        await mPreference.clear();
        try {
            let callCount = 0;
            var observer = function (key) {
                console.log("multiProcessChange observer received key: " + key);
                callCount++;
                if (callCount === 2) {
                    // Observer should be called for each change
                    expect(2).assertEqual(callCount);
                    mPreference.off('multiProcessChange', observer);
                    done();
                }
            }
            mPreference.on('multiProcessChange', observer);

            // Trigger changes
            await mPreference.put("key1", "value1");
            await mPreference.put("key2", "value2");
            await mPreference.flush();
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect().assertFail()
            mPreference.off('multiProcessChange', observer);
            done();
        }
    })

    // Test multiple observers of different types can coexist
    it('testPreferencesMixedObservers001', 0, async function (done) {
        console.log("testPreferencesMixedObservers001 begin.")
        await mPreference.clear();
        try {
            let changeCount = 0;
            let dataChangeCount = 0;
            let multiProcessCount = 0;
            let totalNotifications = 0;

            var checkCompletion = function () {
                totalNotifications++;
                // All three observer types should receive notifications: 2 + 1 + 2 = 5 total
                if (totalNotifications === 5) {
                    expect(2).assertEqual(changeCount);
                    expect(1).assertEqual(dataChangeCount);
                    expect(2).assertEqual(multiProcessCount);
                    mPreference.off('change', changeObserver);
                    mPreference.off('dataChange', ['key1', 'key2'], dataChangeObserver);
                    mPreference.off('multiProcessChange', multiProcessObserver);
                    done();
                }
            }

            var changeObserver = function (_key) {
                changeCount++;
                checkCompletion();
            }
            var dataChangeObserver = function (_data) {
                dataChangeCount++;
                checkCompletion();
            }
            var multiProcessObserver = function (_key) {
                multiProcessCount++;
                checkCompletion();
            }

            mPreference.on('change', changeObserver);
            mPreference.on('dataChange', ['key1', 'key2'], dataChangeObserver);
            mPreference.on('multiProcessChange', multiProcessObserver);

            await mPreference.put("key1", "value1");
            await mPreference.put("key2", "value2");
            await mPreference.flush();
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect().assertFail()
            mPreference.off('change', changeObserver);
            mPreference.off('dataChange', ['key1', 'key2'], dataChangeObserver);
            mPreference.off('multiProcessChange', multiProcessObserver);
            done();
        }
    })

    // Test observer notification order with flush
    it('testPreferencesObserverFlushOrder001', 0, async function (done) {
        console.log("testPreferencesObserverFlushOrder001 begin.")
        await mPreference.clear();
        try {
            let notificationReceived = false;
            var observer = function (key) {
                console.log("observer received key: " + key);
                notificationReceived = true;
                // Observer should be called after flush
                expect(true).assertEqual(notificationReceived);
                mPreference.off('change', observer);
                done();
            }
            mPreference.on('change', observer);

            await mPreference.put("key1", "value1");
            // Observer should not be called before flush
            expect(false).assertEqual(notificationReceived);

            await mPreference.flush();
        } catch (err) {
            console.log("trycatch err =" + err + ", code =" + err.code + ", message =" + err.message)
            expect().assertFail()
            mPreference.off('change', observer);
            done();
        }
    })
})