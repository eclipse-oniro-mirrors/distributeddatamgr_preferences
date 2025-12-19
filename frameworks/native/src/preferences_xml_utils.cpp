/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "preferences_xml_utils.h"
#include "base64_helper.h"
#include <sys/stat.h>

#include <cerrno>
#include <cstring>
#include <sstream>

#include "libxml/parser.h"
#include <libxml/xmlwriter.h>
#include "log_print.h"
#include "preferences_dfx_adapter.h"
#include "preferences_file_lock.h"
#include "preferences_file_operation.h"
#include "preferences_utils.h"

namespace OHOS {
namespace NativePreferences {
constexpr int TOO_MANY_OPEN_FILES = 24;
constexpr int PRE_ALLOCATE_BUFFER_SIZE = 128;
constexpr int NO_SPACE_LEFT_ON_DEVICE = 28;
constexpr int DISK_QUOTA_EXCEEDED = 122;
constexpr int REQUIRED_KEY_NOT_AVAILABLE = 126;
constexpr int REQUIRED_KEY_REVOKED = 128;

constexpr const char *TAG_PREFERENCES = "preferences";
constexpr const char *TAG_VERSION = "version";
constexpr const char *VERSION_VALUE = "1.0";
constexpr const char *ATTR_KEY = "key";
constexpr const char *ATTR_VALUE = "value";

static bool ParseNodeElement(const xmlNode *node, Element &element);
static bool ParsePrimitiveNodeElement(const xmlNode *node, Element &element);
static bool ParseStringNodeElement(const xmlNode *node, Element &element);
static bool ParseArrayNodeElement(const xmlNode *node, Element &element);

struct ValueVisitor {
    std::string_view typeTag;
    std::string valueStr;
    std::string_view childrenTag;
    std::vector<std::string> arrayValues;

    void operator()(int val)
    {
        typeTag = "int";
        valueStr = std::to_string(val);
    }

    void operator()(bool val)
    {
        typeTag = "bool";
        valueStr = val ? "true" : "false";
    }

    void operator()(int64_t val)
    {
        typeTag = "long";
        valueStr = std::to_string(val);
    }

    void operator()(uint64_t val)
    {
        typeTag = "uint64_t";
        valueStr = std::to_string(val);
    }

    void operator()(float val)
    {
        typeTag = "float";
        valueStr = std::to_string(val);
    }

    void operator()(double val)
    {
        typeTag = "double";
        valueStr = std::to_string(val);
    }

    void operator()(const std::string& val)
    {
        typeTag = "string";
        valueStr = val;
    }

    void operator()(const std::vector<std::string>& val)
    {
        typeTag = "stringArray";
        childrenTag = "string";
        arrayValues.reserve(val.size());
        for (const auto& s : val) {
            arrayValues.push_back(s);
        }
    }

    void operator()(const std::vector<double>& val)
    {
        typeTag = "doubleArray";
        childrenTag = "double";
        arrayValues.reserve(val.size());
        for (const auto& d : val) {
            arrayValues.push_back(std::to_string(d));
        }
    }

    void operator()(const std::vector<bool>& val)
    {
        typeTag = "boolArray";
        childrenTag = "bool";
        arrayValues.reserve(val.size());
        for (const auto& b : val) {
            arrayValues.push_back(b ? "true" : "false");
        }
    }

    void operator()(const std::vector<uint8_t>& val)
    {
        typeTag = "uint8Array";
        valueStr = Base64Helper::Encode(val);
    }

    void operator()(const Object& val)
    {
        typeTag = "object";
        valueStr = val.valueStr;
    }

    void operator()(const BigInt& val)
    {
        typeTag = "BigInt";
        childrenTag = "uint64_t";
        arrayValues.reserve(val.words_.size() + 1);
        for (const auto& word : val.words_) {
            arrayValues.push_back(std::to_string(word));
        }
        arrayValues.push_back(std::to_string(static_cast<uint64_t>(val.sign_)));
    }

    void operator()(const std::vector<int>& val)
    {
        typeTag = "intArray";
        childrenTag = "int";
        arrayValues.clear();
        arrayValues.reserve(val.size());
        for (const auto& i : val) {
            arrayValues.push_back(std::to_string(i));
        }
    }

    void operator()(const std::vector<int64_t>& val)
    {
        typeTag = "int64Array";
        childrenTag = "int64";
        arrayValues.clear();
        arrayValues.reserve(val.size());
        for (const auto& i : val) {
            arrayValues.push_back(std::to_string(i));
        }
    }

    void operator()(const std::monostate&)
    {
        typeTag = "unknown";
        LOG_ERROR("Encountered unknown type in PreferencesValue");
    }
};

class XmlWriterWrapper {
public:
    explicit XmlWriterWrapper(xmlTextWriterPtr writer) : writer_(writer) {}
    ~XmlWriterWrapper()
    {
        if (writer_) {
            xmlFreeTextWriter(writer_);
        }
    }

    xmlTextWriterPtr get() const
    {
        return writer_;
    }
private:
    xmlTextWriterPtr writer_;
};

class XmlBufferWrapper {
public:
    explicit XmlBufferWrapper(xmlBufferPtr buffer) : buffer_(buffer) {}
    ~XmlBufferWrapper()
    {
        if (buffer_) {
            xmlBufferFree(buffer_);
        }
    }

    xmlBufferPtr get() const
    {
        return buffer_;
    }
private:
    xmlBufferPtr buffer_;
};

#define XML_CHECK(expr, msg)                                                                        \
    do {                                                                                            \
        if (!(expr)) {                                                                              \
            const xmlError *xmlErr = xmlGetLastError();                                                 \
            LOG_ERROR("%{public}s. Error: %{public}s", msg, xmlErr ? xmlErr->message : "Unknown");  \
            return false;                                                                           \
        }                                                                                           \
    } while (0)

template<typename T>
std::string GetTypeName()
{
    return "unknown";
}

template<>
std::string GetTypeName<int>()
{
    return "int";
}

template<>
std::string GetTypeName<bool>()
{
    return "bool";
}

template<>
std::string GetTypeName<int64_t>()
{
    return "long";
}

template<>
std::string GetTypeName<uint64_t>()
{
    return "uint64_t";
}

template<>
std::string GetTypeName<float>()
{
    return "float";
}

template<>
std::string GetTypeName<double>()
{
    return "double";
}

template<>
std::string GetTypeName<std::string>()
{
    return "string";
}

template<>
std::string GetTypeName<std::vector<std::string>>()
{
    return "stringArray";
}

template<>
std::string GetTypeName<std::vector<double>>()
{
    return "doubleArray";
}

template<>
std::string GetTypeName<std::vector<bool>>()
{
    return "boolArray";
}

template<>
std::string GetTypeName<std::vector<uint8_t>>()
{
    return "uint8Array";
}

template<>
std::string GetTypeName<Object>()
{
    return "object";
}

template<>
std::string GetTypeName<BigInt>()
{
    return "BigInt";
}

template<>
std::string GetTypeName<std::vector<int>>()
{
    return "intArray";
}

template<>
std::string GetTypeName<std::vector<int64_t>>()
{
    return "int64Array";
}

template<typename T>
static void Convert2PrefValue(const Element &element, T &value)
{
    if constexpr (std::is_same<T, std::string>::value) {
        value = element.value_;
    } else if constexpr (std::is_same<T, bool>::value) {
        value = (element.value_.compare("true") == 0) ? true : false;
    } else if constexpr (std::is_same<T, std::monostate>::value) {
        value = std::monostate();
    } else {
        std::stringstream ss;
        ss << element.value_;
        ss >> value;
    }
}

template<typename T>
static void Convert2PrefValue(const Element &element, std::vector<T> &values)
{
    for (const auto &child : element.children_) {
        T value;
        Convert2PrefValue(child, value);
        values.push_back(value);
    }
}

static void Convert2PrefValue(const Element &element, BigInt &value)
{
    for (const auto &child : element.children_) {
        uint64_t val;
        Convert2PrefValue(child, val);
        value.words_.push_back(val);
    }
    value.sign_ = 0;
    if (!value.words_.empty()) {
        value.sign_ = static_cast<int>(value.words_[value.words_.size() - 1]);
        value.words_.pop_back();
    }
}

template<typename T>
bool GetPrefValue(const Element &element, T &value)
{
    LOG_WARN("unknown element type. the key is %{public}s", Anonymous::ToBeAnonymous(element.key_).c_str());
    return false;
}

static void Convert2PrefValue(const Element &element, std::vector<uint8_t> &value)
{
    if (!Base64Helper::Decode(element.value_, value)) {
        value.clear();
    }
}

static void Convert2PrefValue(const Element &element, Object &value)
{
    value.valueStr = element.value_;
}

template<typename T, typename First, typename... Types>
bool GetPrefValue(const Element &element, T &value)
{
    if (element.tag_ == GetTypeName<First>()) {
        First val;
        Convert2PrefValue(element, val);
        value = val;
        return true;
    }
    return GetPrefValue<T, Types...>(element, value);
}

template<typename... Types>
bool Convert2PrefValue(const Element &element, std::variant<Types...> &value)
{
    return GetPrefValue<decltype(value), Types...>(element, value);
}

void ReadXmlElement(const Element &element, std::unordered_map<std::string, PreferencesValue> &prefConMap)
{
    PreferencesValue value(static_cast<int64_t>(0));
    if (Convert2PrefValue(element, value.value_)) {
        prefConMap.insert({element.key_, value});
    }
}

static bool IsFileExist(const std::string &inputPath)
{
    if (inputPath.length() > PATH_MAX) {
        return false;
    }
    struct stat buffer;
    return (stat(inputPath.c_str(), &buffer) == 0);
}

static void RemoveBackupFile(const std::string &fileName)
{
    std::string backupFileName = PreferencesUtils::MakeFilePath(fileName, PreferencesUtils::STR_BACKUP);
    if (IsFileExist(backupFileName) && std::remove(backupFileName.c_str())) {
        LOG_WARN("failed to delete backup file %{public}d.", errno);
    }
}

static xmlDoc *ReadFile(const std::string &fileName, int &errCode)
{
    xmlDoc *doc = xmlReadFile(fileName.c_str(), "UTF-8", XML_PARSE_NOBLANKS | XML_PARSE_HUGE);
    errCode = errno;
    return doc;
}

static void ReportXmlFileCorrupted(const std::string &fileName, const std::string &bundleName,
    const std::string &operationMsg, int errCode)
{
    ReportParam reportParam = { bundleName, NORMAL_DB, ExtractFileName(fileName),
        E_ERROR, errCode, operationMsg };
    PreferencesDfxManager::Report(reportParam, EVENT_NAME_DB_CORRUPTED);
    ReportParam succreportParam = reportParam;
    succreportParam.errCode = E_OK;
    succreportParam.errnoCode = 0;
    succreportParam.appendix = "restore success";
    PreferencesDfxManager::Report(succreportParam, EVENT_NAME_DB_CORRUPTED);
}

static bool ReportNonCorruptError(
    const std::string &faultType, const std::string &fileName, const std::string &bundleName, int errCode)
{
    if (errCode == REQUIRED_KEY_NOT_AVAILABLE || errCode == REQUIRED_KEY_REVOKED) {
        ReportFaultParam reportParam = { faultType, bundleName, NORMAL_DB, ExtractFileName(fileName),
            E_OPERAT_IS_LOCKED, faultType + " the screen is locked." };
        PreferencesDfxManager::ReportAbnormalOperation(reportParam, ReportedFaultBitMap::USE_WHEN_SCREEN_LOCKED);
        return true;
    }
    if (errCode == NO_SPACE_LEFT_ON_DEVICE || errCode == DISK_QUOTA_EXCEEDED || errCode == TOO_MANY_OPEN_FILES) {
        ReportFaultParam param = { faultType, bundleName, NORMAL_DB, ExtractFileName(fileName),
            E_ERROR, faultType + " " + std::strerror(errCode)};
        PreferencesDfxManager::ReportFault(param);
        return true;
    }
    return false;
}

static bool RenameFromBackupFile(
    const std::string &fileName, const std::string &bundleName, bool &isReportCorrupt, bool &isBakFileExist)
{
    std::string backupFileName = PreferencesUtils::MakeFilePath(fileName, PreferencesUtils::STR_BACKUP);
    if (!IsFileExist(backupFileName)) {
        isBakFileExist = false;
        LOG_DEBUG("the backup file does not exist.");
        return false;
    }
    isBakFileExist = true;
    xmlResetLastError();
    int errCode = 0;
    auto bakDoc = std::shared_ptr<xmlDoc>(ReadFile(backupFileName, errCode),
        [](xmlDoc *bakDoc) { xmlFreeDoc(bakDoc); });
    if (bakDoc == nullptr) {
        const xmlError *xmlErr = xmlGetLastError();
        std::string errMessage = (xmlErr != nullptr) ? xmlErr->message : "null";
        LOG_ERROR("%{public}s restore failed, errno:%{public}d, error:%{public}s.",
            ExtractFileName(fileName).c_str(), errCode, errMessage.c_str());
        std::remove(backupFileName.c_str());
        if (ReportNonCorruptError("read bak failed", fileName, bundleName, errCode)) {
            return false;
        }
        isReportCorrupt = true;
        return false;
    }
    if (std::rename(backupFileName.c_str(), fileName.c_str())) {
        LOG_ERROR("failed to restore backup errno %{public}d.", errno);
        return false;
    }
    isReportCorrupt = false;
    struct stat fileStats;
    if (stat(fileName.c_str(), &fileStats) == -1) {
        LOG_ERROR("failed to stat backup file.");
    }
    std::string appindex = "Restored from the backup. The file size is " + std::to_string(fileStats.st_size) + ".";
    ReportFaultParam reportParam = { "read failed", bundleName, NORMAL_DB, ExtractFileName(fileName),
        E_XML_RESTORED_FROM_BACKUP_FILE, appindex };
    PreferencesDfxManager::ReportAbnormalOperation(reportParam, ReportedFaultBitMap::RESTORE_FROM_BAK);
    LOG_INFO("%{public}s restored", ExtractFileName(fileName).c_str());
    return true;
}

static bool RenameFile(const std::string &fileName, const std::string &fileType)
{
    std::string name = PreferencesUtils::MakeFilePath(fileName, fileType);
    if (std::rename(fileName.c_str(), name.c_str())) {
        LOG_ERROR("failed to rename to %{public}s, err:%{public}d.", fileType.c_str(), errno);
        return false;
    }
    return true;
}

static bool RenameToBackupFile(const std::string &fileName)
{
    return RenameFile(fileName, PreferencesUtils::STR_BACKUP);
}

static bool RenameToBrokenFile(const std::string &fileName)
{
    return RenameFile(fileName, PreferencesUtils::STR_BROKEN);
}

static xmlDoc *XmlReadFile(const std::string &fileName, const std::string &bundleName)
{
    xmlDoc *doc = nullptr;
    bool isReport = false;
    bool isMultiProcessing = false;
    PreferencesFileLock fileLock(fileName);
    fileLock.ReadLock(isMultiProcessing);
    int errCode = 0;
    std::string errMessage;
    if (IsFileExist(fileName)) {
        LOG_INFO("file:%{public}s, m:%{public}d.", ExtractFileName(fileName).c_str(), isMultiProcessing);
        doc = ReadFile(fileName, errCode);
        if (doc != nullptr) {
            return doc;
        }
        const xmlError *xmlErr = xmlGetLastError();
        errMessage = (xmlErr != nullptr) ? xmlErr->message : "null";
        LOG_ERROR("failed to read:%{public}s, errno:%{public}d, error:%{public}s.",
            ExtractFileName(fileName).c_str(), errCode, errMessage.c_str());
        if (ReportNonCorruptError("read failed", fileName, bundleName, errCode)) {
            return nullptr;
        }
        if (!RenameToBrokenFile(fileName)) {
            return doc;
        }
        isReport = true;
    }

    bool isExist = true;
    if (RenameFromBackupFile(fileName, bundleName, isReport, isExist)) {
        int bakErrCode = 0;
        doc = ReadFile(fileName, bakErrCode);
        const xmlError *xmlErr = xmlGetLastError();
        std::string message = (xmlErr != nullptr) ? xmlErr->message : "null";
        errMessage.append(" bak: errno is " + std::to_string(bakErrCode) + ", errMessage is " + message);
    }
    if (isMultiProcessing) {
        ReportFaultParam param = { "read failed", bundleName, NORMAL_DB, ExtractFileName(fileName),
            E_OPERAT_IS_CROSS_PROESS, "Cross-process operations." };
        PreferencesDfxManager::ReportFault(param);
        return doc;
    }
    if (isReport) {
        ReportFaultParam param = { "read failed", bundleName, NORMAL_DB, ExtractFileName(fileName),
            E_ERROR, "read failed, " + errMessage};
        isExist ? ReportXmlFileCorrupted(fileName, bundleName, errMessage, errCode) :
            PreferencesDfxManager::ReportFault(param);
    }
    return doc;
}

/* static */
bool PreferencesXmlUtils::ReadSettingXml(const std::string &fileName, const std::string &bundleName,
    std::unordered_map<std::string, PreferencesValue> &conMap)
{
    if (fileName.size() == 0) {
        LOG_ERROR("The length of the file name is 0.");
        return false;
    }
    auto doc =
        std::shared_ptr<xmlDoc>(XmlReadFile(fileName, bundleName), [](xmlDoc *doc) { xmlFreeDoc(doc); });
    if (doc == nullptr) {
        return false;
    }

    xmlNode *root = xmlDocGetRootElement(doc.get());
    if (!root || xmlStrcmp(root->name, reinterpret_cast<const xmlChar *>("preferences"))) {
        LOG_ERROR("Failed to obtain the XML root element.");
        return false;
    }

    bool success = true;
    const xmlNode *cur = nullptr;
    for (cur = root->children; cur != nullptr; cur = cur->next) {
        Element element;

        if (ParseNodeElement(cur, element)) {
            ReadXmlElement(element, conMap);
        } else {
            success = false;
            LOG_ERROR("The error occurred during getting xml child elements.");
            break;
        }
    }
    return success;
}

/* static */
bool ParseNodeElement(const xmlNode *node, Element &element)
{
    if (!xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("string"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("uint8Array"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("object"))) {
        return ParseStringNodeElement(node, element);
    }

    if (!xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("int"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("int64"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("long"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("bool"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("float"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("double"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("uint64_t"))) {
        return ParsePrimitiveNodeElement(node, element);
    }

    if (!xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("boolArray"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("stringArray"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("doubleArray"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("intArray"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("int64Array"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("BigInt"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("set"))) {
        return ParseArrayNodeElement(node, element);
    }

    std::string keyName;
    xmlChar *key = xmlGetProp(node, (const xmlChar *)ATTR_KEY);
    if (key != nullptr) {
        keyName = std::string(reinterpret_cast<char *>(key));
        xmlFree(key);
    }
    LOG_ERROR("An unsupported element type was encountered in parsing = %{public}s, keyName = %{public}s.", node->name,
        Anonymous::ToBeAnonymous(keyName).c_str());
    return false;
}

/* static */
bool ParsePrimitiveNodeElement(const xmlNode *node, Element &element)
{
    xmlChar *key = xmlGetProp(node, reinterpret_cast<const xmlChar *>(ATTR_KEY));
    xmlChar *value = xmlGetProp(node, reinterpret_cast<const xmlChar *>(ATTR_VALUE));

    bool success = false;
    if (value != nullptr) {
        element.tag_ = std::string(reinterpret_cast<const char *>(node->name));
        if (key != nullptr) {
            element.key_ = std::string(reinterpret_cast<char *>(key));
        }
        element.value_ = std::string(reinterpret_cast<char *>(value));
        success = true;
    } else {
        LOG_ERROR("Failed to obtain a valid key or value when parsing %{public}s.", node->name);
    }

    if (key != nullptr) {
        xmlFree(key);
    }
    if (value != nullptr) {
        xmlFree(value);
    }
    return success;
}

/* static */
bool ParseStringNodeElement(const xmlNode *node, Element &element)
{
    xmlChar *key = xmlGetProp(node, (const xmlChar *)ATTR_KEY);
    xmlChar *text = xmlNodeGetContent(node);

    bool success = false;
    if (text != nullptr) {
        element.tag_ = std::string(reinterpret_cast<const char *>(node->name));
        if (key != nullptr) {
            element.key_ = std::string(reinterpret_cast<char *>(key));
        }
        element.value_ = std::string(reinterpret_cast<char *>(text));
        success = true;
    } else {
        LOG_ERROR("Failed to obtain a valid key or value when parsing string element.");
    }

    if (key != nullptr) {
        xmlFree(key);
    }
    if (text != nullptr) {
        xmlFree(text);
    }
    return success;
}

/* static */
bool ParseArrayNodeElement(const xmlNode *node, Element &element)
{
    xmlChar *key = xmlGetProp(node, (const xmlChar *)ATTR_KEY);
    const xmlNode *children = node->children;

    bool success = false;
    if (key != nullptr) {
        element.tag_ = std::string(reinterpret_cast<const char *>(node->name));
        element.key_ = std::string(reinterpret_cast<char *>(key));

        const xmlNode *cur = nullptr;
        bool finishTravelChild = true;
        for (cur = children; cur != nullptr; cur = cur->next) {
            Element child;
            if (ParseNodeElement(cur, child)) {
                element.children_.push_back(child);
            } else {
                finishTravelChild = false;
                LOG_ERROR("Failed to parse the Array element and could not be completed successfully.");
                break;
            }
        }
        success = finishTravelChild;
    } else {
        LOG_ERROR("Failed to obtain a valid key or value when parsing a Array element.");
    }

    if (key != nullptr) {
        xmlFree(key);
    }
    return success;
}

static void ReportSaveFileFault(const std::string fileName, const std::string &bundleName,
    bool &isReport, bool isMultiProcessing)
{
    int errCode = errno;
    bool isExist = false;
    const xmlError *xmlErr = xmlGetLastError();
    std::string errMessage = (xmlErr != nullptr) ? xmlErr->message : "null";
    LOG_ERROR("Save:%{public}s, errno:%{public}d, error:%{public}s.",
        ExtractFileName(fileName).c_str(), errCode, errMessage.c_str());
    if (IsFileExist(fileName)) {
        RenameToBrokenFile(fileName);
        isReport = true;
    }
    RenameFromBackupFile(fileName, bundleName, isReport, isExist);
    if (ReportNonCorruptError("write failed", fileName, bundleName, errCode)) {
        return;
    }
    if (isMultiProcessing) {
        ReportFaultParam param = { "write failed", bundleName, NORMAL_DB, ExtractFileName(fileName),
            E_OPERAT_IS_CROSS_PROESS, "Cross-process operations." };
        PreferencesDfxManager::ReportFault(param);
        return;
    }
    if (isReport) {
        ReportFaultParam param = { "write failed", bundleName, NORMAL_DB, ExtractFileName(fileName),
            E_ERROR, "write failed, " + errMessage};
        isExist ? ReportXmlFileCorrupted(fileName, bundleName, errMessage, errCode) :
            PreferencesDfxManager::ReportFault(param);
    }
}

static bool SaveXmlFile(const std::string &fileName, const std::string &bundleName, xmlBufferPtr buf)
{
    bool isReport = false;
    bool isMultiProcessing = false;
    PreferencesFileLock fileLock(fileName);
    fileLock.WriteLock(isMultiProcessing);
    LOG_INFO("file:%{public}s, m:%{public}d.", ExtractFileName(fileName).c_str(), isMultiProcessing);
    if (IsFileExist(fileName) && !RenameToBackupFile(fileName)) {
        return false;
    }
    int fd = Open(fileName.c_str());
    if (fd == -1) {
        LOG_ERROR("failed open:%{public}s", ExtractFileName(fileName).c_str());
        ReportSaveFileFault(fileName, bundleName, isReport, isMultiProcessing);
        return false;
    }
    if (Write(fd, buf->content, buf->use) < 0) {
        LOG_ERROR("Failed write:%{public}s", ExtractFileName(fileName).c_str());
        ReportSaveFileFault(fileName, bundleName, isReport, isMultiProcessing);
        Close(fd);
        return false;
    }
    if (!Fsync(fd)) {
        LOG_WARN("Failed to write to the disk.");
    }
    Close(fd);
    RemoveBackupFile(fileName);
    return true;
}

static bool WriteXmlElement(xmlTextWriterPtr writer, const std::string &key, const PreferencesValue &value)
{
    ValueVisitor visitor;
    std::visit(visitor, value.value_);
    const char* tag = visitor.typeTag.data();
    const char* keyPtr = key.c_str();
    if (visitor.typeTag == "string" || visitor.typeTag == "uint8Array" || visitor.typeTag == "object") {
        XML_CHECK(xmlTextWriterStartElement(writer, BAD_CAST tag) >= 0, "Start element failed");
        XML_CHECK(xmlTextWriterWriteAttribute(writer, BAD_CAST ATTR_KEY, BAD_CAST keyPtr) >= 0, "Write attr failed");
        XML_CHECK(xmlTextWriterWriteString(writer, BAD_CAST visitor.valueStr.c_str()) >= 0, "Write value failed");
        XML_CHECK(xmlTextWriterEndElement(writer) >= 0, "End element failed");
    } else if (visitor.typeTag == "int" || visitor.typeTag == "long" ||visitor.typeTag == "float" ||
        visitor.typeTag == "bool" || visitor.typeTag == "double") {
        XML_CHECK(xmlTextWriterStartElement(writer, BAD_CAST tag) >= 0, "Start element failed");
        XML_CHECK(xmlTextWriterWriteAttribute(writer, BAD_CAST ATTR_KEY, BAD_CAST keyPtr) >= 0, "Write attr failed");
        XML_CHECK(xmlTextWriterWriteAttribute(writer, BAD_CAST ATTR_VALUE, BAD_CAST visitor.valueStr.c_str()) >= 0,
            "Write attr failed");
        XML_CHECK(xmlTextWriterEndElement(writer) >= 0, "End element failed");
    } else if (visitor.typeTag == "intArray" || visitor.typeTag == "int64Array" ||
        visitor.typeTag == "doubleArray" || visitor.typeTag == "stringArray" ||
        visitor.typeTag == "boolArray" || visitor.typeTag == "BigInt") {
        XML_CHECK(xmlTextWriterStartElement(writer, BAD_CAST tag) >= 0, "Start element failed");
        XML_CHECK(xmlTextWriterWriteAttribute(writer, BAD_CAST ATTR_KEY, BAD_CAST keyPtr) >= 0, "Write attr failed");
        for (auto &child : visitor.arrayValues) {
            if (visitor.childrenTag == "string") {
                XML_CHECK(xmlTextWriterStartElement(writer, BAD_CAST visitor.childrenTag.data()) >= 0,
                    "Start element failed");
                XML_CHECK(xmlTextWriterWriteString(writer, BAD_CAST child.c_str()) >= 0, "Write value failed");
                XML_CHECK(xmlTextWriterEndElement(writer) >= 0, "End element failed");
            } else {
                XML_CHECK(xmlTextWriterStartElement(writer, BAD_CAST visitor.childrenTag.data()) >= 0,
                    "Start element failed");
                XML_CHECK(xmlTextWriterWriteAttribute(writer, BAD_CAST ATTR_VALUE, BAD_CAST child.c_str()) >= 0,
                    "Write attr failed");
                XML_CHECK(xmlTextWriterEndElement(writer) >= 0, "End element failed");
            }
        }
        XML_CHECK(xmlTextWriterEndElement(writer) >= 0, "End element failed");
    }
    return true;
}

/* static */
bool PreferencesXmlUtils::WriteSettingXml(const std::string &fileName, const std::string &bundleName,
    const std::unordered_map<std::string, PreferencesValue> &writeToDiskMap)
{
    if (fileName.empty()) {
        LOG_ERROR("The length of the file name is 0.");
        return false;
    }

    XmlBufferWrapper bufferWrapper(xmlBufferCreateSize(writeToDiskMap.size() * PRE_ALLOCATE_BUFFER_SIZE));
    if (!bufferWrapper.get()) {
        LOG_ERROR("Failed to create XML buffer");
        return false;
    }
    XmlWriterWrapper writerWrapper(xmlNewTextWriterMemory(bufferWrapper.get(), 0));
    if (!writerWrapper.get()) {
        LOG_ERROR("Failed to create XML writer");
        return false;
    }

    xmlTextWriterPtr writer = writerWrapper.get();
    xmlTextWriterSetIndent(writer, 0);

    XML_CHECK(xmlTextWriterStartDocument(writer, nullptr, "UTF-8", nullptr) >= 0, "Start document failed");
    XML_CHECK(xmlTextWriterStartElement(writer, BAD_CAST TAG_PREFERENCES) >= 0, "Start root element failed");
    XML_CHECK(xmlTextWriterWriteAttribute(writer, BAD_CAST TAG_VERSION, BAD_CAST VERSION_VALUE) >= 0,
            "Write version failed");

    for (const auto& [key, prefValue] : writeToDiskMap) {
        if (!WriteXmlElement(writer, key, prefValue)) {
            return false;
        }
    }

    XML_CHECK(xmlTextWriterEndElement(writer) >= 0, "End root failed");
    XML_CHECK(xmlTextWriterEndDocument(writer) >= 0, "End document failed");

    return SaveXmlFile(fileName, bundleName, bufferWrapper.get());
}
} // End of namespace NativePreferences
} // End of namespace OHOS