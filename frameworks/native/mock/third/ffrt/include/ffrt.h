/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_PREFERENCES_FFRT_MOCK_H
#define OHOS_PREFERENCES_FFRT_MOCK_H
 
#include <vector>
#include <functional>
#include <atomic>
 
namespace ffrt {
 
typedef struct {
    uint32_t storage[4];
} ffrt_task_attr_t;
 
class task_attr : public ffrt_task_attr_t {
public:
    inline task_attr &qos(int32_t) { return *this;}
};
 
typedef enum {
    /** Data dependency type. */
    ffrt_dependence_data,
    /** Task dependency type. */
    ffrt_dependence_task,
} ffrt_dependence_type_t;
 
typedef struct {
    const void* ptr;
    /** Dependency type. */
    ffrt_dependence_type_t type;
} ffrt_dependence_t;
 
struct dependence : ffrt_dependence_t {
    dependence() = default;
    dependence(const char* ptr) {
    }
};
 
inline void submit(std::function<void()>&& func, std::initializer_list<dependence> in_deps,
    dependence out_deps, const task_attr& attr = {})
{
    return;
}
}
 
#endif // OHOS_PREFERENCES_FFRT_MOCK_H