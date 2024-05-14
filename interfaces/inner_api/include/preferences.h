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

#ifndef PREFERENCES_H
#define PREFERENCES_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "preferences_errno.h"
#include "preferences_observer.h"
#include "preferences_value.h"
#include "preferences_visibility.h"

namespace OHOS {
namespace NativePreferences {
using RegisterMode = PreferencesObserver::RegisterMode;
struct Options {
public:
    Options(const std::string inputFilePath) : filePath(inputFilePath)
    {
    }

    Options(const char *inputFilePath) : filePath(inputFilePath)
    {
    }

    Options(const std::string &inputFilePath, const std::string &inputbundleName, const std::string &inputdataGroupId)
        : filePath(inputFilePath), bundleName(inputbundleName), dataGroupId(inputdataGroupId)
    {
    }

public:
    std::string filePath{ "" };
    std::string bundleName{ "" };
    std::string dataGroupId{ "" };
};
/**
 * The function class of the preference. Various operations on preferences instances are provided in this class.
 */
class PREF_API_EXPORT Preferences {
public:
    PREF_API_EXPORT virtual ~Preferences()
    {
    }

    /**
    * @brief The constant Indicates the maximum length of the key in the preferences.
    */
    PREF_API_EXPORT static constexpr uint32_t MAX_KEY_LENGTH = 80;

    /**
     * @brief The constant Indicates the maximum length of the value in the preferences.
     */
    PREF_API_EXPORT static constexpr uint32_t MAX_VALUE_LENGTH = 8 * 1024;

    /**
     * @brief Obtains the value of a preferences.
     *
     * This function is used to get the value of the corresponding key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param defValue Indicates the default value of the preferences.
     *
     * @return Returns the value matching the specified key if it is found; returns the default value otherwise.
     */
    virtual PreferencesValue Get(const std::string &key, const PreferencesValue &defValue) = 0;

    /**
     * @brief Sets a value for the key in the preferences.
     *
     *  This function is used to set or update the value of the corresponding key in the preferences.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param value Indicates the default value of the preferences.
     *
     * @return Returns 0 for success, others for failure.
     */
    virtual int Put(const std::string &key, const PreferencesValue &value) = 0;

    /**
     * @brief Obtains the int value of a preferences.
     *
     * This function is used to get an int value of the corresponding key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param defValue Indicates the default value of the preferences.
     *
     * @return Returns a int value matching the specified key if it is found; returns the default value otherwise.
     */
    virtual int GetInt(const std::string &key, const int &defValue = {}) = 0;

    /**
     * @brief Obtains the string value of a preferences.
     *
     * This function is used to get string value of the corresponding key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param defValue Indicates the default value of the preferences.
     *
     * @return Returns string value matching the specified key if it is found; returns the default value otherwise.
     */
    virtual std::string GetString(const std::string &key, const std::string &defValue = {}) = 0;

    /**
     * @brief Obtains the bool value of a preferences.
     *
     * This function is used to get a bool value of the corresponding key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param defValue Indicates the default value of the preferences.
     *
     * @return Returns a bool value matching the specified key if it is found; returns the default value otherwise.
     */
    virtual bool GetBool(const std::string &key, const bool &defValue = {}) = 0;

    /**
     * @brief Obtains the float value of a preferences.
     *
     * This function is used to get a float value of the corresponding key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param defValue Indicates the default value of the preferences.
     *
     * @return Returns a float value matching the specified key if it is found; returns the default value otherwise.
     */
    virtual float GetFloat(const std::string &key, const float &defValue = {}) = 0;

    /**
     * @brief Obtains the double value of a preferences.
     *
     * This function is used to get a double value of the corresponding key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param defValue Indicates the default value of the preferences.
     *
     * @return Returns a double value matching the specified key if it is found; returns the default value otherwise.
     */
    virtual double GetDouble(const std::string &key, const double &defValue = {}) = 0;

    /**
     * @brief Obtains the long value of a preferences.
     *
     * This function is used to get a long value of the corresponding key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param defValue Indicates the default value of the preferences.
     *
     * @return Returns a long value matching the specified key if it is found; returns the default value otherwise.
     */
    virtual int64_t GetLong(const std::string &key, const int64_t &defValue = {}) = 0;

    /**
     * @brief Obtains all the keys and values of a preferences.
     *
     * This function is used to get all keys and values in an object.
     *
     * @return Returns a map, the key is string type and the value is PreferencesValue type.
     */
    virtual std::map<std::string, PreferencesValue> GetAll() = 0;

    /**
     * @brief Checks whether contains a preferences matching a specified key.
     *
     * This function is used to Checks whether contains a preferences matching a specified key.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     *
     * @return Returning true means it contains, false means it doesn't.
     */
    virtual bool HasKey(const std::string &key) = 0;

    /**
     * @brief Put or update an int value of a preferences.
     *
     * This function is used to put or update an int value of the corresponding key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param value Indicates the value of preferences to put or update.
     *
     * @return Returns 0 for success, others for failure.
     */
    virtual int PutInt(const std::string &key, int value) = 0;

    /**
     * @brief Put or update an string value for the key.
     *
     * This function is used to put or update string value of the corresponding key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param value Indicates the value of preferences to put or update.
     *
     * @return Returns 0 for success, others for failure.
     */
    virtual int PutString(const std::string &key, const std::string &value) = 0;

    /**
     * @brief Put or update bool string value for the key.
     *
     * This function is used to put or update a bool value of the corresponding key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param value Indicates the value of preferences to put or update.
     *
     * @return Returns 0 for success, others for failure.
     */
    virtual int PutBool(const std::string &key, bool value) = 0;

    /**
     * @brief Put or update an long value for the key.
     *
     * This function is used to put or update a long value of the corresponding key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param value Indicates the value of preferences to put or update.
     *
     * @return Returns 0 for success, others for failure.
     */
    virtual int PutLong(const std::string &key, int64_t value) = 0;

    /**
     * @brief Put or update an float value for the key.
     *
     * This function is used to put or update a float value of the corresponding key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param value Indicates the value of preferences to put or update.
     *
     * @return Returns 0 for success, others for failure.
     */
    virtual int PutFloat(const std::string &key, float value) = 0;

    /**
     * @brief Put or update an double value for the key.
     *
     * This function is used to put or update a double value of the corresponding key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     * @param value Indicates the value of preferences to put or update.
     *
     * @return Returns 0 for success, others for failure.
     */
    virtual int PutDouble(const std::string &key, double value) = 0;

    /**
     * @brief Deletes the preferences with a specified key.
     *
     * This function is used to delete the preferences with a specified key in the preference.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     *
     * @return Returns 0 for success, others for failure.
     */
    virtual int Delete(const std::string &key) = 0;

    /**
     * @brief Clears all preferences.
     *
     * This function is used to clear all preferences in an object.
     *
     * @return Returns 0 for success, others for failure.
     */
    virtual int Clear() = 0;

    /**
     * @brief Asynchronously saves the preferences to the file.
     *
     * This function is used to saves the preferences to the file. Files are written to disk only after
     * this interface or {@link FlushSync}is called.
     */
    virtual void Flush() = 0;

    /**
     * @brief Synchronously saves the preferences to the file.
     *
     * This function is used to saves the preferences to the file synchronously. Files are written to disk only after
     * this interface or {@link Flush} is called.
     *
     * @return The result of write to disk. Returns 0 for success, others for failure.
     */
    virtual int FlushSync() = 0;

    /**
     * @brief  Registers an observer.
     *
     * This function is used to registers an observer to listen for the change of a preferences.
     *
     * @param preferencesObserver Indicates callback function for data changes.
     */
    virtual int RegisterObserver(
        std::shared_ptr<PreferencesObserver> preferencesObserver, RegisterMode mode = RegisterMode::LOCAL_CHANGE) = 0;

    int Subscribe(std::shared_ptr<PreferencesObserver> observer, RegisterMode mode = RegisterMode::LOCAL_CHANGE,
        const std::vector<std::string> &keys = {})
    {
        switch (mode) {
            case RegisterMode::LOCAL_CHANGE:
            case RegisterMode::MULTI_PRECESS_CHANGE:
                return RegisterObserver(observer, mode);
            case RegisterMode::DATA_CHANGE:
                return RegisterDataObserver(observer, keys);
            default:
                break;
        }
        return E_INVALID_ARGS;
    }

    /**
     * @brief  Unregister an existing observer.
     *
     * This function is used to unregister an existing observer.
     *
     * @param preferencesObserver Indicates callback function for data changes.
     */
    virtual int UnRegisterObserver(
        std::shared_ptr<PreferencesObserver> preferencesObserver, RegisterMode mode = RegisterMode::LOCAL_CHANGE) = 0;

    int Unsubscribe(std::shared_ptr<PreferencesObserver> observer, RegisterMode mode = RegisterMode::LOCAL_CHANGE,
        const std::vector<std::string> &keys = {})
    {
        switch (mode) {
            case RegisterMode::LOCAL_CHANGE:
            case RegisterMode::MULTI_PRECESS_CHANGE:
                return UnRegisterObserver(observer, mode);
            case RegisterMode::DATA_CHANGE:
                return UnRegisterDataObserver(observer, keys);
            default:
                break;
        }
        return E_INVALID_ARGS;
    }

    /**
     * @brief  Get group id.
     *
     * This function is used to Get group id.
     *
     * @return Returns the groupId when it exists, otherwise returns an empty string.
     */
    virtual std::string GetGroupId() const
    {
        return "";
    }

    /**
     * @brief  Registers a data observer.
     *
     * This function is used to registers an observer to listen for changes in data based on the keys
     *
     * @param preferencesObserver Indicates callback function for data changes.
     */
    virtual int RegisterDataObserver(
        std::shared_ptr<PreferencesObserver> preferencesObserver, const std::vector<std::string> &keys = {})
    {
        return E_OK;
    }

    /**
     * @brief  Unregister an existing observer.
     *
     * This function is used to unregister an existing observer based on the keys
     *
     * @param preferencesObserver Indicates callback function for data changes.
     */
    virtual int UnRegisterDataObserver(
        std::shared_ptr<PreferencesObserver> preferencesObserver, const std::vector<std::string> &keys = {})
    {
        return E_OK;
    }
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_H
