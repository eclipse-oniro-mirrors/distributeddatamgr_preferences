/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef PREFERENCES_ADAPTOR_H
#define PREFERENCES_ADAPTOR_H

#ifndef FILE_MODE
#define FILE_MODE 0771
#endif

#ifndef FILE_EXIST
#define FILE_EXIST 0
#endif

#define DO_NOTHING

#ifdef WINDOWS_PLATFORM
#include <unistd.h>
#include <iostream>
#define REALPATH(filePath, realPath, ...) (_fullpath(realPath, filePath, ##__VA_ARGS__))
#define MKDIR(filePath) (mkdir(filePath))
#define ACCESS(filePath) (_access(filePath, FILE_EXIST))
#define DISTRIBUTED_DATA_HITRACE(trace) DO_NOTHING

#elif MAC_PLATFORM
#include <stdarg.h>
#include <sys/stat.h>
#include <unistd.h>
#define REALPATH(filePath, realPath, ...) (realpath(filePath, realPath))
#define MKDIR(filePath) (mkdir(filePath, FILE_MODE))
#define ACCESS(filePath) (access(filePath, FILE_EXIST))
#define DISTRIBUTED_DATA_HITRACE(trace) DO_NOTHING

#else
#include <stdarg.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdlib>
#include "hitrace.h"
#define REALPATH(filePath, realPath, ...) (realpath(filePath, realPath))
#define MKDIR(filePath) (mkdir(filePath, FILE_MODE))
#define ACCESS(filePath) (access(filePath, FILE_EXIST))
#define DISTRIBUTED_DATA_HITRACE(trace) HiTrace hitrace(trace)

#endif

#ifndef INT_MAX
#define INT_MAX 2147483647
#endif

#endif // PREFERENCES_ADAPTOR_H