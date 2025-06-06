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

#ifndef OHOS_PREFERENCES_FRAMEWORKS_COMMON_VISIBILITY_H
#define OHOS_PREFERENCES_FRAMEWORKS_COMMON_VISIBILITY_H

#ifndef API_EXPORT
#define API_EXPORT __attribute__((visibility("default")))
#endif
#ifndef API_LOCAL
#define API_LOCAL __attribute__((visibility("hidden")))
#endif
#ifndef UNUSED_FUNCTION
#define UNUSED_FUNCTION __attribute__((unused))
#endif

#endif // OHOS_PREFERENCES_FRAMEWORKS_COMMON_VISIBILITY_H
