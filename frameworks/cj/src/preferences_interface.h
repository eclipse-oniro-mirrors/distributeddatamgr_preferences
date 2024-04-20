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
#ifndef PREFERENCES_INTERFACE_H
#define PREFERENCES_INTERFACE_H

#include <cstdint>
#include <string>
#include "preferences_errno.h"
#include "preferences.h"
#include "securec.h"

namespace OHOS {
namespace Preferences {

struct CArrBool {
    bool* head;
    int64_t size;
};

struct CArrStr {
    char** head;
    int64_t size;
};

struct CArrDouble {
    double* head;
    int64_t size;
};

struct ValueType {
    int64_t integer;
    double float64;
    char* string;
    bool boolean;
    CArrBool boolArray;
    CArrDouble doubleArray;
    CArrStr stringArray;
    uint8_t tag;
};

struct ValueTypes {
    char** key;
    ValueType* head;
    int64_t size;
};

struct HelperAysncContext {
    std::string path;
    std::string name;
    std::string bundleName;
    std::string dataGroupId;
    std::shared_ptr<NativePreferences::Preferences> proxy;

    HelperAysncContext()
    {
    }
    virtual ~HelperAysncContext(){};
};

} // namespace Preferences
} // namespace OHOS

#endif