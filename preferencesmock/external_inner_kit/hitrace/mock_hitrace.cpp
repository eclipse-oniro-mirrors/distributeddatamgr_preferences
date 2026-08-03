/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "hitrace_meter.h"

void StartTrace(const TraceLabel &label)
{
}

void FinishTrace(const TraceLabel &label)
{
}

void StartAsyncTrace(const TraceLabel &label, uint64_t taskId)
{
}

void FinishAsyncTrace(const TraceLabel &label, uint64_t taskId)
{
}

int HitraceMeter::TraceInit()
{
    return 0;
}

int HitraceMeter::TraceStart(const TraceLabel &label)
{
    return 0;
}

int HitraceMeter::TraceFinish(const TraceLabel &label)
{
    return 0;
}