/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_CONVERTOR_H
#define OH_CONVERTOR_H

#include "oh_preferences_option.h"
#include "preferences.h"

namespace OHOS::PreferencesNdk {
class OHConvertor final {
public:
    static int NativeErrToNdk(int nativeErrCode);
    static OHOS::NativePreferences::StorageType NdkStorageTypeToNative(const Preferences_StorageType &type);
private:
    OHConvertor() = default;
    ~OHConvertor() = default;
};

}   // namespace OHOS::PreferencesNdk
#endif // OH_CONVERTOR_H