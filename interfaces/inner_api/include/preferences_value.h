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

#include "preferences_visibility.h"

namespace OHOS {
namespace NativePreferences {
struct Object {
    std::string valueStr;
    Object() = default;
    Object(const std::string &str) : valueStr(str) {};
    bool operator==(const Object &other) const
    {
        return valueStr == other.valueStr;
    }
};

struct BigInt {
public:
    BigInt() = default;
    BigInt(const std::vector<uint64_t> &words, int sign) : words_(std::move(words)), sign_(sign)
    {
    }
    ~BigInt() = default;
    bool operator==(const BigInt &value) const
    {
        return sign_ == value.sign_ && words_ == value.words_;
    }
    std::vector<uint64_t> words_;
    int sign_;
};

/**
 * The PreferencesValue class of the preference. Various operations on PreferencesValue are provided in this class.
 */
class PREF_API_EXPORT PreferencesValue {
public:
    PREF_API_EXPORT PreferencesValue()
    {
        value_ = std::monostate();
    }

    PREF_API_EXPORT ~PreferencesValue()
    {
    }

    /**
     * @brief Move constructor.
     */
    PREF_API_EXPORT PreferencesValue(PreferencesValue &&preferencesValue) noexcept;

    /**
     * @brief Copy constructor.
     */
    PREF_API_EXPORT PreferencesValue(const PreferencesValue &preferencesValue);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the int input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates an int input parameter.
     */
    PREF_API_EXPORT PreferencesValue(int value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the int64_t input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a int64_t input parameter.
     */
    PREF_API_EXPORT PreferencesValue(int64_t value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the int64_t input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a int64_t input parameter.
     */
    PREF_API_EXPORT PreferencesValue(float value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the double input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a double input parameter.
     */
    PREF_API_EXPORT PreferencesValue(double value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the bool input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a bool input parameter.
     */
    PREF_API_EXPORT PreferencesValue(bool value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the string input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates string input parameter.
     */
    PREF_API_EXPORT PreferencesValue(std::string value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the char input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a char input parameter.
     */
    PREF_API_EXPORT PreferencesValue(const char *value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the vector<double> input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a vector<double> input parameter.
     */
    PREF_API_EXPORT PreferencesValue(std::vector<double> value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the vector<std::string> input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a vector<std::string> input parameter.
     */
    PREF_API_EXPORT PreferencesValue(std::vector<std::string> value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the vector<bool> input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a vector<bool> input parameter.
     */
    PREF_API_EXPORT PreferencesValue(std::vector<bool> value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the vector<uint8_t> input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a vector<uint8_t> input parameter.
     */
    PREF_API_EXPORT PreferencesValue(std::vector<uint8_t> value);

    PREF_API_EXPORT PreferencesValue(Object value);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the BigInt input parameter to a value of type PreferencesValue.
     *
     * @param value Indicates a vector<uint8_t> input parameter.
     */
    PREF_API_EXPORT PreferencesValue(BigInt value);

    /**
     * @brief Move assignment operator overloaded function.
     */
    PREF_API_EXPORT PreferencesValue &operator=(PreferencesValue &&preferencesValue) noexcept;

    /**
     * @brief Copy assignment operator overloaded function.
     */
    PreferencesValue &operator=(const PreferencesValue &preferencesValue);

    /**
     * @brief Determines whether the int type PreferencesValue is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    PREF_API_EXPORT bool IsInt() const;

    /**
     * @brief Determines whether the long type PreferencesValue is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    PREF_API_EXPORT bool IsLong() const;

    /**
     * @brief Determines whether the float type PreferencesValue is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    PREF_API_EXPORT bool IsFloat() const;

    /**
     * @brief Determines whether the double type PreferencesValue is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    PREF_API_EXPORT bool IsDouble() const;

    /**
     * @brief Determines whether the bool type PreferencesValue is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    PREF_API_EXPORT bool IsBool() const;

    /**
     * @brief Determines whether the string type PreferencesValue is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    PREF_API_EXPORT bool IsString() const;

    /**
     * @brief Determines whether the string array type PreferencesValue is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    PREF_API_EXPORT bool IsStringArray() const;

    /**
     * @brief Determines whether the bool array type PreferencesValue is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    PREF_API_EXPORT bool IsBoolArray() const;

    /**
     * @brief Determines whether the double array type PreferencesValue is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    PREF_API_EXPORT bool IsDoubleArray() const;

    /**
     * @brief Determines whether the uint8 array type PreferencesValue is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    PREF_API_EXPORT bool IsUint8Array() const;

    PREF_API_EXPORT bool IsObject() const;

    /**
     * @brief Determines whether the BigInt type PreferencesValue is currently used.
     *
     * @return Returning true means it is, false means it isn't.
     */
    PREF_API_EXPORT bool IsBigInt() const;

    /**
     * @brief Type conversion function.
     *
     * @return The int type PreferencesValue.
     */
    PREF_API_EXPORT operator int() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns float type PreferencesValue.
     */
    PREF_API_EXPORT operator float() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns double type PreferencesValue.
     */
    PREF_API_EXPORT operator double() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns bool type PreferencesValue.
     */
    PREF_API_EXPORT operator bool() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns int64_t type PreferencesValue.
     */
    PREF_API_EXPORT operator int64_t() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns string type PreferencesValue.
     */
    PREF_API_EXPORT operator std::string() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns vector<double> type PreferencesValue.
     */
    PREF_API_EXPORT operator std::vector<double>() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns vector<bool> type PreferencesValue.
     */
    PREF_API_EXPORT operator std::vector<bool>() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns vector<string> type PreferencesValue.
     */
    PREF_API_EXPORT operator std::vector<std::string>() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns vector<uint8_t> type PreferencesValue.
     */
    PREF_API_EXPORT operator std::vector<uint8_t>() const;

    PREF_API_EXPORT operator Object() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns BigInt type PreferencesValue.
     */
    PREF_API_EXPORT operator BigInt() const;

    /**
     * @brief Overloaded operator "==".
     *
     * This function is used to determine whether the input value is equal to the current PreferencesValue.
     *
     * @param value Indicates a PreferencesValue.
     *
     * @return Returning true means the input value is equal to the current PreferencesValue, false means it isn't.
     */
    PREF_API_EXPORT bool operator==(const PreferencesValue &value);

    std::variant<std::monostate, int, int64_t, float, double, bool, std::string, std::vector<std::string>,
        std::vector<bool>, std::vector<double>, std::vector<uint8_t>, Object, BigInt> value_;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_VALUE_H
