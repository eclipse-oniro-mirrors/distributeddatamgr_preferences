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

#include "preferences_radar_reporter.h"
#include "hisysevent.h"
#include "preferences_errno.h"

namespace OHOS {
namespace NativePreferences {

PreferencesRadar::PreferencesRadar(Scene scene, const char* funcName) : scene_(scene), funcName_(funcName)
{
    if (funcName_ == nullptr) {
        funcName_ = UNKNOW;
    }
    LocalReport(scene_, funcName_, STATE_START);
}

PreferencesRadar::~PreferencesRadar()
{
    LocalReport(scene_, funcName_, STATE_FINISH, errCode_);
}

PreferencesRadar& PreferencesRadar::operator=(int errCode)
{
    errCode_ = errCode;
    return *this;
}

PreferencesRadar::operator int() const
{
    return errCode_;
}

void PreferencesRadar::LocalReport(int bizSence, const char* funcName, int state, int errCode)
{
    int stageRes = static_cast<int>(StageRes::RES_SUCCESS);
    if (errCode != E_OK) {
        stageRes = static_cast<int>(StageRes::RES_FAILED);
    }

    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::DISTRIBUTED_DATAMGR,
        PreferencesRadar::EVENT_NAME,
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        PreferencesRadar::ORG_PKG_LABEL, PreferencesRadar::ORG_PKG_VALUE,
        PreferencesRadar::FUNC_LABEL, funcName,
        PreferencesRadar::BIZ_SCENE_LABEL, bizSence,
        PreferencesRadar::BIZ_STAGE_LABEL, LocalStage::LOCAL_IMPLEMENT,
        PreferencesRadar::STAGE_RES_LABEL, stageRes,
        PreferencesRadar::ERROR_CODE_LABEL, errCode,
        PreferencesRadar::BIZ_STATE_LABEL, state);
    return;
}
}
}