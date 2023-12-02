/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PREFERENCES_FILE_LOCK_H
#define PREFERENCES_FILE_LOCK_H

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "preferences_errno.h"
namespace OHOS {
namespace NativePreferences {

class PreferencesLockManager {
public:
    static std::shared_ptr<std::mutex> Get(const std::string fileName);
private:
    static std::map<std::string, std::shared_ptr<std::mutex>> inProcessMutexs_;
    static std::mutex mapMutex_;
};
class PreferencesFileLock final {
public:
    PreferencesFileLock(const std::string &path, const std::string &dataGroupId);
    ~PreferencesFileLock();

private:
    int fd_{ -1 };
    std::shared_ptr<std::mutex> inProcessMutex_;
};
} // namespace NativePreferences
} // namespace OHOS
#endif