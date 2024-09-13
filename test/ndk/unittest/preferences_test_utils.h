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

#ifndef PREFERENCES_TEST_UTILS_H
#define PREFERENCES_TEST_UTILS_H

#include <string>

#include "oh_preferences.h"

namespace OHOS {
namespace PreferencesNdk {

class NdkTestUtils {
public:
    static void CreateDirectoryRecursively(const std::string &path);
};
} // End of namespace PreferencesNdk
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_TEST_UTILS_H