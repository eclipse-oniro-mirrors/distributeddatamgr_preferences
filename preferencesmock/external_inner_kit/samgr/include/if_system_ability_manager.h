/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef DATA_FABRIC_ADDRESS_MOCK_IF_SYSTEM_ABILITY_MANAGER_H
#define DATA_FABRIC_ADDRESS_MOCK_IF_SYSTEM_ABILITY_MANAGER_H

#include <cstdint>
#include <list>
#include <string>
#include <vector>

#include "iremote_broker.h"
#include "iremote_object.h"
#include "message_parcel.h"

namespace OHOS {
struct SAExtraProp {
    bool isDistributed = false;
    bool isSACallBack = false;
    int32_t dumpLevel = 0;
};

struct SystemProcessInfo {
    std::string name;
    int32_t pid;
    int32_t uid;
};

struct SystemAbilityOnDemandEvent {
    std::string name;
    int32_t value;
};

enum class OnDemandPolicyType : int32_t {
    LOAD_POLICY = 0,
    UNLOAD_POLICY = 1,
};

struct SaExtensionInfo {
    std::string name;
    int32_t saId;
};

class ISystemAbilityStatusChange : public IRemoteBroker {
public:
    virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) = 0;
    virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"ISystemAbilityStatusChange");
};

class ISystemAbilityLoadCallback : public IRemoteBroker {
public:
    virtual void OnLoadSystemAbilitySuccess(int32_t systemAbilityId,
        const sptr<IRemoteObject> &remoteObject) = 0;
    virtual void OnLoadSystemAbilityFail(int32_t systemAbilityId) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"ISystemAbilityLoadCallback");
};

class ISystemProcessStatusChange : public IRemoteBroker {
public:
    virtual void OnSystemProcessStatusChange(SystemProcessInfo &processInfo) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"ISystemProcessStatusChange");
};

class ISystemAbilityManager : public IRemoteBroker {
public:
    virtual std::vector<std::u16string> ListSystemAbilities(unsigned int systemAbilityNum) = 0;
    virtual sptr<IRemoteObject> GetSystemAbility(int32_t systemAbilityId) = 0;
    virtual sptr<IRemoteObject> GetSystemAbility(int32_t systemAbilityId,
        const std::string &deviceId) = 0;
    virtual sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId) = 0;
    virtual sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId,
        const std::string &deviceId) = 0;
    virtual sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId, bool &isExist) = 0;
    virtual int32_t RemoveSystemAbility(int32_t systemAbilityId) = 0;
    virtual int32_t SubscribeSystemAbility(int32_t systemAbilityId,
        const sptr<ISystemAbilityStatusChange> &callback) = 0;
    virtual int32_t UnSubscribeSystemAbility(int32_t systemAbilityId,
        const sptr<ISystemAbilityStatusChange> &callback) = 0;
    virtual int32_t AddOnDemandSystemAbilityInfo(int32_t systemAbilityId,
        const std::u16string &localAbilityName) = 0;
    virtual int32_t AddSystemAbility(int32_t systemAbilityId,
        const sptr<IRemoteObject> &ability, const SAExtraProp &extraProp) = 0;
    virtual int32_t AddSystemProcess(const std::u16string &name,
        const sptr<IRemoteObject> &processObject) = 0;
    virtual sptr<IRemoteObject> LoadSystemAbility(int32_t systemAbilityId, int32_t timeout) = 0;
    virtual int32_t LoadSystemAbility(int32_t systemAbilityId,
        const sptr<ISystemAbilityLoadCallback> &callback) = 0;
    virtual int32_t LoadSystemAbility(int32_t systemAbilityId, const std::string &deviceId,
        const sptr<ISystemAbilityLoadCallback> &callback) = 0;
    virtual int32_t UnloadSystemAbility(int32_t systemAbilityId) = 0;
    virtual int32_t CancelUnloadSystemAbility(int32_t systemAbilityId) = 0;
    virtual int32_t UnloadAllIdleSystemAbility() = 0;
    virtual int32_t GetSystemProcessInfo(int32_t systemAbilityId, SystemProcessInfo &processInfo) = 0;
    virtual int32_t GetRunningSystemProcess(std::list<SystemProcessInfo> &processInfo) = 0;
    virtual int32_t SubscribeSystemProcess(
        const sptr<ISystemProcessStatusChange> &processChangeListener) = 0;
    virtual int32_t UnSubscribeSystemProcess(
        const sptr<ISystemProcessStatusChange> &processChangeListener) = 0;
    virtual int32_t SendStrategy(int32_t systemAbilityId, std::vector<int32_t> &pidList,
        int32_t strategy, std::string &reason) = 0;
    virtual int32_t GetOnDemandReasonExtraData(int64_t extraDataId, MessageParcel &extraDataParcel) = 0;
    virtual int32_t GetOnDemandPolicy(int32_t systemAbilityId, OnDemandPolicyType policyType,
        std::vector<SystemAbilityOnDemandEvent> &onDemandEvents) = 0;
    virtual int32_t UpdateOnDemandPolicy(int32_t systemAbilityId, OnDemandPolicyType policyType,
        const std::vector<SystemAbilityOnDemandEvent> &onDemandEvents) = 0;
    virtual int32_t GetOnDemandSystemAbilityIds(std::vector<int32_t> &systemAbilityIds) = 0;
    virtual int32_t GetExtensionSaIds(const std::string &extensionName,
        std::vector<int32_t> &saIds) = 0;
    virtual int32_t GetExtensionRunningSaList(const std::string &extensionName,
        std::vector<sptr<IRemoteObject>> &saList) = 0;
    virtual int32_t GetRunningSaExtensionInfoList(const std::string &extensionName,
        std::vector<SaExtensionInfo> &saExtensionInfos) = 0;
    virtual int32_t GetCommonEventExtraDataIdlist(int32_t systemAbilityId,
        std::vector<int64_t> &extraDataIds, const std::string &type) = 0;
    virtual sptr<IRemoteObject> GetLocalAbilityManagerProxy(int32_t systemAbilityId) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.sysabilitymgr.samgr");
};
} // namespace OHOS
#endif // DATA_FABRIC_ADDRESS_MOCK_IF_SYSTEM_ABILITY_MANAGER_H
