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

#ifndef OHOS_PREFERENCES_FRAMEWORKS_COMMON_TASK_SCHEDULER_H
#define OHOS_PREFERENCES_FRAMEWORKS_COMMON_TASK_SCHEDULER_H
#include <pthread.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <thread>

#include "visibility.h"
namespace OHOS {
class API_LOCAL TaskScheduler {
public:
    using TaskId = uint64_t;
    using Time = std::chrono::steady_clock::time_point;
    using Task = std::function<void()>;
    inline static constexpr TaskId INVALID_TASK_ID = static_cast<uint64_t>(0ULL);
    TaskScheduler(const std::string &name)
    {
        capacity_ = std::numeric_limits<size_t>::max();
        isRunning_ = true;
        taskId_ = INVALID_TASK_ID;
        thread_ = std::make_unique<std::thread>([this, name]() {
            auto realName = std::string("task_queue_") + name;
#if defined(MAC_PLATFORM) || defined(IOS_PLATFORM)
            pthread_setname_np(realName.c_str());
#else
            pthread_setname_np(pthread_self(), realName.c_str());
#endif
            Loop();
        });
    }

    ~TaskScheduler()
    {
        isRunning_ = false;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            indexes_.clear();
            tasks_.clear();
        }
        At(std::chrono::steady_clock::now(), []() {});
        thread_->join();
    }

    // execute task at specific time
    TaskId At(const Time &time, Task task)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (tasks_.size() >= capacity_) {
            return INVALID_TASK_ID;
        }
        auto taskId = GenTaskId();
        auto it = tasks_.insert({ time, std::pair{ task, taskId } });
        if (it == tasks_.begin()) {
            condition_.notify_one();
        }
        indexes_[taskId] = it;
        return taskId;
    }
    
    TaskId Execute(Task task)
    {
        return At(std::chrono::steady_clock::now(), std::move(task));
    }

private:
    using InnerTask = std::pair<std::function<void()>, uint64_t>;
    void Loop()
    {
        while (isRunning_) {
            std::function<void()> exec;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                condition_.wait(lock, [this] { return !tasks_.empty(); });
                auto it = tasks_.begin();
                exec = it->second.first;
                indexes_.erase(it->second.second);
                tasks_.erase(it);
            }

            if (exec) {
                exec();
            }
        }
    }

    TaskId GenTaskId()
    {
        auto taskId = ++taskId_;
        if (taskId == INVALID_TASK_ID) {
            return ++taskId_;
        }
        return taskId;
    }

    volatile bool isRunning_;
    size_t capacity_;
    std::multimap<Time, InnerTask> tasks_;
    std::map<TaskId, decltype(tasks_)::iterator> indexes_;
    std::mutex mutex_;
    std::unique_ptr<std::thread> thread_;
    std::condition_variable condition_;
    std::atomic<uint64_t> taskId_;
};
} // namespace OHOS
#endif // OHOS_PREFERENCES_FRAMEWORKS_COMMON_TASK_SCHEDULER_H
