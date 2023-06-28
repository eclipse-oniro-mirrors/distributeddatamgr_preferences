/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {beforeAll, beforeEach, describe, afterEach, afterAll, expect, it} from 'deccjsunit/index';
import dataPreferences from '@ohos.data.preferences'
import featureAbility from '@ohos.ability.featureAbility';

const NAME = 'test_preferences';
const BASE_COUNT = 2000;
const BASELINE = 25000;
const KEY_TEST_STRING_KEY = 'key_test_string';
const KEY_TEST_STRING_VAL = '0123456789';

var mPreference;
var context;

const TAG = '[SUB_DDM_PERF_PreferencesOperationSyncJsPref]'

describe("PreferencesOperationSyncJsPref", async function () {
    beforeAll(async function () {
        console.info(`${TAG}beforeAll`)
        context = featureAbility.getContext()
        mPreference = await dataPreferences.getPreferences(context, NAME);
    })

    beforeEach(async function () {
        console.info(`${TAG}beforeEach`);
    })

    afterEach(async function () {
        console.info(`${TAG}afterEach`);
    })

    afterAll(async function () {
        console.info(`${TAG}afterAll`)
        await dataPreferences.deletePreferences(context, NAME);
    })

    /**
     * @tc.desc PreferencesOperationSyncJsPref_PutSync
     */
    it("putSync_0001", 0, async function () {
        let startTime = new Date().getTime(); // time unit is mm
        for (let index = 0; index < BASE_COUNT; index++) {
            mPreference.putSync(KEY_TEST_STRING_KEY, KEY_TEST_STRING_VAL);
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(`${TAG}putSync_0001 averageTime: ${averageTime} us`);
        expect(averageTime < BASELINE).assertTrue();
    })

    /**
     * @tc.desc PreferencesOperationSyncJsPref_GetSync
     */
    it("getSync_0001", 0, async function () {
        let startTime = new Date().getTime(); // time unit is mm
        for (let index = 0; index < BASE_COUNT; index++) {
            mPreference.getSync(KEY_TEST_STRING_KEY, KEY_TEST_STRING_VAL);
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(`${TAG}getSync_0001 averageTime: ${averageTime} us`);
        expect(averageTime < BASELINE).assertTrue();
    })

    /**
     * @tc.desc PreferencesOperationSyncJsPref_HasSync
     */
    it("hasSync_0001", 0, async function () {
        let startTime = new Date().getTime(); // time unit is mm
        for (let index = 0; index < BASE_COUNT; index++) {
            mPreference.hasSync(KEY_TEST_STRING_KEY);
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(`${TAG}hasSync_0001 averageTime: ${averageTime} us`);
        expect(averageTime < BASELINE).assertTrue();

    })

    /**
     * @tc.desc PreferencesOperationSyncJsPref_GetAllSync
     */
    it("getAllSync_0001", 0, async function () {
        let startTime = new Date().getTime(); // time unit is mm
        for (let index = 0; index < BASE_COUNT; index++) {
            mPreference.getAllSync();
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(`${TAG}getAllSync_0001 averageTime: ${averageTime} us`);
        expect(averageTime < BASELINE).assertTrue();
    })
})