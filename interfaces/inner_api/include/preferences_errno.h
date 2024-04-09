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

#ifndef PREFERENCES_ERRNO_H
#define PREFERENCES_ERRNO_H

#include <errno.h>

namespace OHOS {
namespace NativePreferences {

/**
* @brief The error code in the correct case.
*/
constexpr int E_OK = 0;

/**
* @brief The base code of the exception error code.
*/
constexpr int E_BASE = 15500000;

/**
* @brief The error when the capability not supported.
*/
constexpr int E_NOT_SUPPORTED = 801;

/**
* @brief The error code for common exceptions.
*/
constexpr int E_ERROR = E_BASE;

/**
* @brief The error code for resource has been stopped, killed or destroyed.
*/
constexpr int E_STALE = (E_BASE + 1); // Resource has been stopped, killed or destroyed.

/**
* @brief The error code for the input args is invalid.
*/
constexpr int E_INVALID_ARGS = (E_BASE + 2); // the input args is invalid.

/**
* @brief The error code for out of memory.
*/
constexpr int E_OUT_OF_MEMORY = (E_BASE + 3); // out of memory

/**
* @brief The error code for operation is not permitted.
*/
constexpr int E_NOT_PERMIT = (E_BASE + 4); // operation is not permitted

/**
* @brief The error code for the key is empty.
*/
constexpr int E_KEY_EMPTY = (E_BASE + 5);

/**
* @brief The error code for the key string length exceed the max length (80).
*/
constexpr int E_KEY_EXCEED_MAX_LENGTH = (E_BASE + 6);

/**
* @brief The error code for the former Preferences object pointer is held by another thread and may
* not be able to be deleted.
*/
constexpr int E_PTR_EXIST_ANOTHER_HOLDER = (E_BASE + 7);

/**
* @brief The error code for the file path is relative path.
*/
constexpr int E_RELATIVE_PATH = (E_BASE + 8);

/**
* @brief The error code for the file path is empty.
*/
constexpr int E_EMPTY_FILE_PATH = (E_BASE + 9);

/**
* @brief The error code when deleting a file fails.
*/
constexpr int E_DELETE_FILE_FAIL = (E_BASE + 10);

/**
* @brief The error code for the file name is empty.
*/
constexpr int E_EMPTY_FILE_NAME = (E_BASE + 11);

/**
* @brief The error code for the file path is invalid.
*/
constexpr int E_INVALID_FILE_PATH = (E_BASE + 12);

/**
* @brief The error code for the file path exceeds the max length.
*/
constexpr int E_PATH_EXCEED_MAX_LENGTH = (E_BASE + 13);

/**
* @brief The error code for the value exceeds the max length (8 * 1024).
*/
constexpr int E_VALUE_EXCEED_MAX_LENGTH = (E_BASE + 14);

/**
* @brief The error code for the key exceeds the length limit (32).
*/
constexpr int E_KEY_EXCEED_LENGTH_LIMIT = (E_BASE + 15);

/**
* @brief The error code for the value exceeds the length limit (128).
*/
constexpr int E_VALUE_EXCEED_LENGTH_LIMIT = (E_BASE + 16);

/**
* @brief The error code for the default exceeds the max length (128).
*/
constexpr int E_DEFAULT_EXCEED_LENGTH_LIMIT = (E_BASE + 17);

/**
* @brief The error code for permission denied.
*/
constexpr int PERMISSION_DENIED = (E_BASE + 18);

/**
* @brief Failed to get DataObsMgrClient.
*/
static constexpr int E_GET_DATAOBSMGRCLIENT_FAIL = (E_BASE + 19);

/**
* @brief The error code is used to retain the observer.
*/
constexpr int E_OBSERVER_RESERVE = (E_BASE + 20);

} // namespace NativePreferences
} // namespace OHOS
#endif // PREFERENCES_ERRNO_H
