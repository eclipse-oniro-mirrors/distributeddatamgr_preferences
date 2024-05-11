/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "js_observer.h"

namespace OHOS::PreferencesJsKit {
JSObserver::JSObserver(std::shared_ptr<UvQueue> uvQueue, napi_value callback, bool sendable)
    : uvQueue_(uvQueue), sendabel_(sendable)
{
    napi_create_reference(uvQueue->GetEnv(), callback, 1, &callback_);
}

JSObserver::~JSObserver()
{
}

napi_ref JSObserver::GetCallback()
{
    return callback_;
}

void JSObserver::ClearCallback()
{
    if (callback_ == nullptr) {
        return;
    }
    auto uvQueue = uvQueue_.lock();
    if (uvQueue != nullptr) {
        napi_delete_reference(uvQueue->GetEnv(), callback_);
        callback_ = nullptr;
    }
}


napi_env JSObserver::GetEnv()
{
    auto uvQueue = uvQueue_.lock();
    if (uvQueue != nullptr) {
        return uvQueue->GetEnv();
    }

    return nullptr;
}

void JSObserver::AsyncCall(UvQueue::NapiArgsGenerator genArgs)
{
    if (callback_ == nullptr) {
        return;
    }
    auto uvQueue = uvQueue_.lock();
    if (uvQueue == nullptr) {
        return;
    }
    uvQueue->AsyncCall(
        [observer = shared_from_this()](napi_env env) -> napi_value {
            // the lambda run in js main thread, so it serial run with Clear(), so we can use no lock.
            if (observer->callback_ == nullptr) {
                return nullptr;
            }
            napi_value callback = nullptr;
            napi_get_reference_value(env, observer->callback_, &callback);
            return callback;
        },
        genArgs, sendabel_);
}
} // namespace OHOS::DistributedKVStore
