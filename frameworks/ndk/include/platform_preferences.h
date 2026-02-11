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

#ifndef PLATFORM_PREFERENCES_H
#define PLATFORM_PREFERENCES_H

#if defined(WINDOWS_PLATFORM)
#include <stdlib.h>
#else
#include "securec.h"
#endif

namespace OHOS::PreferencesNdk {
static int SetPoint(void *dest, size_t destMax, int c, size_t count)
{
    int err = 0;
#if defined(WINDOWS_PLATFORM)
    err = memset(dest, c, count);
#else
    err = memset_s(dest, destMax, c, count);
#endif
    return err;
}

static int CpoyPoint(void *dest, size_t destMax, const void *src, size_t count)
{
    int err = 0;
#if defined(WINDOWS_PLATFORM)
    err = memcpy(dest, src, count);
#else
    err = memcpy_s(dest, destMax, src, count);
#endif
    return err;
}

} // namespace OHOS::PreferencesNdk

#endif