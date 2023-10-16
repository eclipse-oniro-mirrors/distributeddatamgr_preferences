// @ts-nocheck
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
var mPref;

describe('StorageHelperJsunit', function () {
    beforeAll(function () {
        console.info('beforeAll')
    })

    beforeEach(function () {
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
     * @tc.name getStorageSync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Storage_0010
     * @tc.desc getStorageSync interface test
     */
    it('testGetStorageHelper001', 0, async function () {
        mPref.putSync('test', 2);
        var value = mPref.getSync('test', 0);
        expect(value).assertEqual(2);
    })

    /**
     * @tc.name getStorage interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Storage_0020
     * @tc.desc getStorage interface test
     */
    it('testGetStorageHelper002', 0, async function () {
        const promise = storage.getStorage(PATH);
        await promise.then((pref) => {
            pref.putSync('test', 2);
            var value = mPref.getSync('test', 0);
            expect(value).assertEqual(2);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name removeStorageFromCacheSync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Storage_0030
     * @tc.desc removeStorageFromCacheSync interface test
     */
    it('testRemoveStorageFromCache001', 0, function () {
        let perf = storage.getStorageSync('/data/storage/el2/database/test_storage1');
        perf.putSync('test', 2);
        perf.flushSync();
        try {
            storage.removeStorageFromCacheSync('/data/storage/el2/database/test_storage1');
        } catch (e) {
            expect(null).assertFail();
        }
        perf = storage.getStorageSync('/data/storage/el2/database/test_storage1');
        var value = perf.getSync('test', 0);
        expect(value).assertEqual(2);
    })
    /**
     * @tc.name removeStorageFromCache interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Storage_0040
     * @tc.desc removeStorageFromCache interface test
     */
    it('testRemoveStorageFromCache002', 0, async function () {
        let perf = storage.getStorageSync('/data/test_storage2');
        perf = null;
        const promise = storage.removeStorageFromCache('/data/test_storage2');
        await promise.then((pref) => {
        }).catch((err) => {
            expect(null).assertFail();
        }); 
    })

    /**
     * @tc.name deleteStorageSync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Storage_0050
     * @tc.desc deleteStorageSync interface test
     */
    it('testDeleteStorageHelper001', 0, function () {
        let perf = storage.getStorageSync('/data/test_storage3');
        try {
            storage.deleteStorageSync('/data/test_storage3');
        } catch (e) {
            expect(null).assertFail();
        }
        try {
            perf.putSync("int", 3);
        } catch (e) {
            expect(null).assertFail();
        }
    })

    /**
     * @tc.name deleteStorage interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Storage_0060
     * @tc.desc deleteStorage interface test
     */
    it('testDeleteStorageHelper002', 0, async function () {
        let perf = storage.getStorageSync('/data/test_storage4');
        perf = null;
        const promise = storage.deleteStorage('/data/test_storage4');
        await promise.then((pref) => {
        }).catch((err) => {
            expect(null).assertFail();
        });
    })
})