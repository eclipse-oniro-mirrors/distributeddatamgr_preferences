/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "preferences_test_utils.h"
#include "oh_preferences.h"
#include "oh_convertor.h"
#include "log_print.h"
#include "oh_preferences_err_code.h"
#include "oh_preferences_impl.h"
#include "oh_preferences_value_impl.h"
#include "oh_preferences_value.h"
#include "preferences_file_operation.h"
#include "preferences_helper.h"

namespace OHOS {
namespace PreferencesNdk {

void NdkTestUtils::CreateDirectoryRecursively(const std::string &path)
{
    std::string::size_type pos = path.find_last_of('/');
    if (pos == std::string::npos || path.front() != '/') {
        printf("path can not be relative path.\n");
    }
    std::string dir = path.substr(0, pos);

    std::string tempDirectory = dir;
    std::vector<std::string> directories;

    pos = tempDirectory.find('/');
    while (pos != std::string::npos) {
        std::string directory = tempDirectory.substr(0, pos);
        if (!directory.empty()) {
            directories.push_back(directory);
        }
        tempDirectory = tempDirectory.substr(pos + 1);
        pos = tempDirectory.find('/');
    }
    directories.push_back(tempDirectory);

    std::string databaseDirectory;
    for (const std::string& directory : directories) {
        databaseDirectory = databaseDirectory + "/" + directory;
        if (OHOS::NativePreferences::Access(databaseDirectory.c_str()) != F_OK) {
            if (OHOS::NativePreferences::Mkdir(databaseDirectory)) {
                printf("failed to mkdir, errno %d, %s \n", errno, databaseDirectory.c_str());
                return;
            }
        }
    }
}

} // End of namespace PreferencesNdk
} // End of namespace OHOS