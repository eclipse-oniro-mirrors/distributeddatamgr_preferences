/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef PREFERENCES_HELPER_H
#define PREFERENCES_HELPER_H

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "preferences.h"

namespace OHOS {
namespace NativePreferences {
class PreferencesHelper {
public:

    /**
     * @brief Obtains a preferences instance matching a specified preferences file name.
     *
     * @param path Indicates the preferences file name
     * @param errCode Indicates the error code. Returns 0 for success, others for failure.
     *
     * @return Returns a Preferences instance matching the specified preferences file name.
     */
    static std::shared_ptr<Preferences> GetPreferences(const std::string &path, int &errCode);

    /**
     * @brief Deletes a preferences instance matching a specified preferences file name.
     *
     * @param path Indicates the preferences file name
     *
     * @return Returns 0 for success, others for failure.
     */
    static int DeletePreferences(const std::string &path);

    /**
     * @brief Remove a preferences instance matching a specified preferences file name from cache.
     *
     * @param path Indicates the preferences file name
     *
     * @return Returns 0 for success, others for failure.
     */
    static int RemovePreferencesFromCache(const std::string &path);

private:
    static std::map<std::string, std::shared_ptr<Preferences>> prefsCache_;
    static std::mutex prefsCacheMutex_;

    static std::string GetRealPath(const std::string &path, int &errorCode);
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_HELPER_H
