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


import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from "@ohos/hypium"
import data_preferences from '@ohos.data.preferences'

const NAME = 'test_preferences';
var context = globalThis.stageContext;
export default function stagePreferencesHelperTest() {
    describe('UnitStagePreferencesHelperTest', function () {
        beforeAll(function() {
            console.info('beforeAll')
        })
        afterAll(async function () {
            console.info('afterAll');
            await data_preferences.deletePreferences(context, NAME);
        })
        /**
        * @tc.name getPreferences
        * @tc.number SUB_DDM_AppDataFWK_JSPreferences_getPreferences_001
        * @tc.desc getPreferences interface test
        */
        it('testGetPreferencesHelper001', 0, async function (done) {
            var mPreferences = await data_preferences.getPreferences(context, NAME);
            await mPreferences.put('test', 2);
            var value = await mPreferences.get('test', 0);
            console.log('cjx testGetPreferencesHelper001 success');
            done();
            expect(value).assertEqual(2);
        })

    })
}