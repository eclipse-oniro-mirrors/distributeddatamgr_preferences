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

#ifndef PREFERENCES_VALUE_H
#define PREFERENCES_VALUE_H

#include <string>
#include <variant>
#include <vector>

namespace OHOS {
namespace NativePreferences {

// The PreferencesValue class of the preference. Various operations on PreferencesValue are provided in this class.
class PreferencesValue {
public:
    ~PreferencesValue()
    {
    }

    /**
     * @brief Move constructor.
     */
    PreferencesValue(PreferencesValue &&preferencesValue) noexcept;

    /**
     * @brief Copy constructor.
     */
    PreferencesValue(const PreferencesValue &preferencesValue);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the int input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates an int input parameter.
     */
    PreferencesValue(int value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the int64_t input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a int64_t input parameter.
     */
    PreferencesValue(int64_t value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the int64_t input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a int64_t input parameter.
     */
    PreferencesValue(float value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the double input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a double input parameter.
     */
    PreferencesValue(double value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the bool input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a bool input parameter.
     */
    PreferencesValue(bool value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the string input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a string input parameter.
     */
    PreferencesValue(std::string value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the char input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a char input parameter.
     */
    PreferencesValue(const char *value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the vector<double> input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a vector<double> input parameter.
     */
    PreferencesValue(std::vector<double> value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the vector<std::string> input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a vector<std::string> input parameter.
     */
    PreferencesValue(std::vector<std::string> value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the vector<bool> input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a vector<bool> input parameter.
     */
    PreferencesValue(std::vector<bool> value);

    /**
     * @brief Move assignment operator overloaded function.
     */
    PreferencesValue &operator=(PreferencesValue &&preferencesValue) noexcept;

    /**
     * @brief Copy assignment operator overloaded function.
     */
    PreferencesValue &operator=(const PreferencesValue &preferencesValue);

    /**
     * @brief Determines whether the int type in _value is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    bool IsInt() const;

    /**
     * @brief Determines whether the long type in _value is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    bool IsLong() const;

    /**
     * @brief Determines whether the float type in _value is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    bool IsFloat() const;

    /**
     * @brief Determines whether the double type in _value is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    bool IsDouble() const;

    /**
     * @brief Determines whether the bool type in _value is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    bool IsBool() const;

    /**
     * @brief Determines whether the string type in _value is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    bool IsString() const;

    /**
     * @brief Determines whether the string array type in _value is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    bool IsStringArray() const;

    /**
     * @brief Determines whether the bool array type in _value is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    bool IsBoolArray() const;

    /**
     * @brief Determines whether the double array type in _value is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    bool IsDoubleArray() const;

    /**
     * @brief Type conversion function.
     *
     * @return The int type value in _value.
     */
    operator int() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns float type value in _value.
     */
    operator float() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns double type value in _value.
     */
    operator double() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns bool type value in _value.
     */
    operator bool() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns int64_t type value in _value.
     */
    operator int64_t() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns string type value in _value.
     */
    operator std::string() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns vector<double> type value in _value.
     */
    operator std::vector<double>() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns vector<bool> type value in _value.
     */
    operator std::vector<bool>() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns vector<string> type value in _value.
     */
    operator std::vector<std::string>() const;

    /**
     * @brief Overloaded operator "==".
     *
     * This function is used to determine whether the input value is the same as the current PreferencesValue.
     *
     * @param value Indicates a PreferencesValue.
     *
     * @return Returning true means this._value is , false means it isn't.
     */
    bool operator==(const PreferencesValue &value);

private:
    std::variant<int, int64_t, float, double, bool, std::string, std::vector<std::string>, std::vector<bool>,
        std::vector<double>>
        value_;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_VALUE_H
