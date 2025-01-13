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

#include <sys/stat.h>

#include <cerrno>
#include <cstring>

#include "libxml/parser.h"
#include "log_print.h"
#include "preferences_dfx_adapter.h"
#include "preferences_file_lock.h"
#include "preferences_file_operation.h"
#include "preferences_impl.h"

namespace OHOS {
namespace NativePreferences {
constexpr int REQUIRED_KEY_NOT_AVAILABLE = 126;
constexpr int REQUIRED_KEY_REVOKED = 128;
static bool ParseNodeElement(const xmlNode *node, Element &element);
static bool ParsePrimitiveNodeElement(const xmlNode *node, Element &element);
static bool ParseStringNodeElement(const xmlNode *node, Element &element);
static bool ParseArrayNodeElement(const xmlNode *node, Element &element);
static xmlNode *CreateElementNode(Element &element);
static xmlNode *CreatePrimitiveNode(Element &element);
static xmlNode *CreateStringNode(Element &element);
static xmlNode *CreateArrayNode(Element &element);

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
    std::string backupFileName = MakeFilePath(fileName, STR_BACKUP);
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
    succreportParam.appendix = "operation: restore success";
    PreferencesDfxManager::Report(succreportParam, EVENT_NAME_DB_CORRUPTED);
}

static void ReportAbnormalOperation(ReportInfo &reportInfo, ReportedFaultBitMap faultOffset)
{
    uint64_t offset = static_cast<uint32_t>(faultOffset);
    PreferencesImpl::reportedFaults_.Compute(
        reportInfo.fileName_, [reportInfo, offset](auto &fileName, uint64_t &report) {
        uint64_t mask = 0x01;
        if ((report >> offset) & mask) {
            return true;
        }
        ReportParam param = { reportInfo.bundleName_, NORMAL_DB, ExtractFileName(reportInfo.fileName_),
            reportInfo.errCode_, reportInfo.errNo_, reportInfo.operationMsg_ };
        PreferencesDfxManager::Report(param, EVENT_NAME_PREFERENCES_FAULT);
        report |= (mask << offset);
        return true;
    });
}

static bool RenameFromBackupFile(const std::string &fileName, const std::string &bundleName, bool &isReportCorrupt)
{
    std::string backupFileName = MakeFilePath(fileName, STR_BACKUP);
    if (!IsFileExist(backupFileName)) {
        LOG_DEBUG("the backup file does not exist.");
        return false;
    }
    xmlResetLastError();
    int errCode = 0;
    auto bakDoc = std::shared_ptr<xmlDoc>(ReadFile(backupFileName, errCode),
        [](xmlDoc *bakDoc) { xmlFreeDoc(bakDoc); });
    if (bakDoc == nullptr) {
        xmlErrorPtr xmlErr = xmlGetLastError();
        std::string errMessage = (xmlErr != nullptr) ? xmlErr->message : "null";
        LOG_ERROR("restore XML file: %{public}s failed, errno is %{public}d, error is %{public}s.",
            ExtractFileName(fileName).c_str(), errCode, errMessage.c_str());
        std::remove(backupFileName.c_str());
        if (errCode == REQUIRED_KEY_NOT_AVAILABLE || errCode == REQUIRED_KEY_REVOKED) {
            std::string operationMsg = "Read bak file when the screen is locked.";
            ReportInfo reportInfo = { E_OPERAT_IS_LOCKED, errCode, fileName, bundleName, operationMsg };
            ReportAbnormalOperation(reportInfo, ReportedFaultBitMap::USE_WHEN_SCREEN_LOCKED);
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
    ReportInfo reportInfo = { E_XML_RESTORED_FROM_BACKUP_FILE, 0, fileName, bundleName, appindex };
    ReportAbnormalOperation(reportInfo, ReportedFaultBitMap::RESTORE_FROM_BAK);
    LOG_INFO("restore XML file %{public}s successfully.", ExtractFileName(fileName).c_str());
    return true;
}

static bool RenameFile(const std::string &fileName, const std::string &fileType)
{
    std::string name = MakeFilePath(fileName, fileType);
    if (std::rename(fileName.c_str(), name.c_str())) {
        LOG_ERROR("failed to rename file to %{public}s file %{public}d.", fileType.c_str(), errno);
        return false;
    }
    return true;
}

static bool RenameToBackupFile(const std::string &fileName)
{
    return RenameFile(fileName, STR_BACKUP);
}

static bool RenameToBrokenFile(const std::string &fileName)
{
    return RenameFile(fileName, STR_BROKEN);
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
        LOG_INFO("read xml file:%{public}s, muti processing status is %{public}d.", ExtractFileName(fileName).c_str(),
            isMultiProcessing);
        doc = ReadFile(fileName, errCode);
        if (doc != nullptr) {
            return doc;
        }
        xmlErrorPtr xmlErr = xmlGetLastError();
        errMessage = (xmlErr != nullptr) ? xmlErr->message : "null";
        LOG_ERROR("failed to read XML format file: %{public}s, errno is %{public}d, error is %{public}s.",
            ExtractFileName(fileName).c_str(), errCode, errMessage.c_str());
        if (errCode == REQUIRED_KEY_NOT_AVAILABLE || errCode == REQUIRED_KEY_REVOKED) {
            std::string operationMsg = "Read Xml file when the screen is locked.";
            ReportInfo reportInfo = { E_OPERAT_IS_LOCKED, errCode, fileName, bundleName, operationMsg };
            ReportAbnormalOperation(reportInfo, ReportedFaultBitMap::USE_WHEN_SCREEN_LOCKED);
            return nullptr;
        }
        if (!RenameToBrokenFile(fileName)) {
            return doc;
        }
        isReport = true;
    }

    if (RenameFromBackupFile(fileName, bundleName, isReport)) {
        int bakErrCode = 0;
        doc = ReadFile(fileName, bakErrCode);
        xmlErrorPtr xmlErr = xmlGetLastError();
        std::string message = (xmlErr != nullptr) ? xmlErr->message : "null";
        errMessage.append(" bak: errno is " + std::to_string(bakErrCode) + ", errMessage is " + message);
    }
    if (!isMultiProcessing) {
        if (isReport) {
            const std::string operationMsg = "operation: failed to read XML format file, errMessage:" + errMessage;
            ReportXmlFileCorrupted(fileName, bundleName, operationMsg, errCode);
        }
    } else {
        ReportParam param = { bundleName, NORMAL_DB, ExtractFileName(fileName),
            E_OPERAT_IS_CROSS_PROESS, errCode, "Cross-process operations exist during file reading."
        };
        PreferencesDfxManager::Report(param, EVENT_NAME_PREFERENCES_FAULT);
    }
    return doc;
}

/* static */
bool PreferencesXmlUtils::ReadSettingXml(const std::string &fileName, const std::string &bundleName,
    std::vector<Element> &settings)
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
            settings.push_back(element);
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
    if (!xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("int"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("long"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("bool"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("float"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("double"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("uint64_t"))) {
        return ParsePrimitiveNodeElement(node, element);
    }

    if (!xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("string"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("uint8Array"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("object"))) {
        return ParseStringNodeElement(node, element);
    }

    if (!xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("boolArray"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("stringArray"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("doubleArray"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("BigInt"))
        || !xmlStrcmp(node->name, reinterpret_cast<const xmlChar *>("set"))) {
        return ParseArrayNodeElement(node, element);
    }

    LOG_ERROR("An unsupported element type was encountered in parsing = %{public}s.", node->name);
    return false;
}

/* static */
bool ParsePrimitiveNodeElement(const xmlNode *node, Element &element)
{
    xmlChar *key = xmlGetProp(node, reinterpret_cast<const xmlChar *>("key"));
    xmlChar *value = xmlGetProp(node, reinterpret_cast<const xmlChar *>("value"));

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
    xmlChar *key = xmlGetProp(node, (const xmlChar *)"key");
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
    xmlChar *key = xmlGetProp(node, (const xmlChar *)"key");
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

static std::pair<bool, int> SaveFormatFileEnc(const std::string &fileName, xmlDoc *doc)
{
    return {xmlSaveFormatFileEnc(fileName.c_str(), doc, "UTF-8", 1) > 0, errno};
}

bool XmlSaveFormatFileEnc(const std::string &fileName, const std::string &bundleName, xmlDoc *doc)
{
    PreferencesFileLock fileLock(fileName);
    bool isMultiProcessing = false;
    fileLock.WriteLock(isMultiProcessing);
    LOG_INFO("save xml file:%{public}s, muti processing status is %{public}d.", ExtractFileName(fileName).c_str(),
        isMultiProcessing);
    if (IsFileExist(fileName) && !RenameToBackupFile(fileName)) {
        return false;
    }

    auto [ret, errCode] = SaveFormatFileEnc(fileName, doc);
    if (!ret) {
        bool isReport = false;
        xmlErrorPtr xmlErr = xmlGetLastError();
        std::string errMessage = (xmlErr != nullptr) ? xmlErr->message : "null";
        LOG_ERROR("failed to save XML format file: %{public}s, errno is %{public}d, error is %{public}s.",
            ExtractFileName(fileName).c_str(), errCode, errMessage.c_str());
        if (errCode == REQUIRED_KEY_NOT_AVAILABLE || errCode == REQUIRED_KEY_REVOKED) {
            std::string operationMsg = "Write Xml file when the screen is locked.";
            ReportInfo reportInfo = { E_OPERAT_IS_LOCKED, errCode, fileName, bundleName, operationMsg };
            ReportAbnormalOperation(reportInfo, ReportedFaultBitMap::USE_WHEN_SCREEN_LOCKED);
            return false;
        }
        if (IsFileExist(fileName)) {
            RenameToBrokenFile(fileName);
            isReport = true;
        }
        RenameFromBackupFile(fileName, bundleName, isReport);
        if (!isMultiProcessing) {
            if (isReport) {
                const std::string operationMsg = "operation: failed to save XML format file, errMessage:" + errMessage;
                ReportXmlFileCorrupted(fileName, bundleName, operationMsg, errCode);
            }
        } else {
            ReportParam param = { bundleName, NORMAL_DB, ExtractFileName(fileName),
                E_OPERAT_IS_CROSS_PROESS, errCode, "Cross-process operations exist during file writing."
            };
            PreferencesDfxManager::Report(param, EVENT_NAME_PREFERENCES_FAULT);
        }
        return false;
    }

    // make sure the file is written to disk.
    if (!Fsync(fileName)) {
        LOG_WARN("failed to write the file to the disk.");
    }

    RemoveBackupFile(fileName);
    PreferencesXmlUtils::LimitXmlPermission(fileName);
    LOG_DEBUG("successfully saved the XML format file");
    return true;
}

/* static */
bool PreferencesXmlUtils::WriteSettingXml(const std::string &fileName, const std::string &bundleName,
    const std::vector<Element> &settings)
{
    if (fileName.size() == 0) {
        LOG_ERROR("The length of the file name is 0.");
        return false;
    }

    // define doc and root Node
    auto doc = std::shared_ptr<xmlDoc>(xmlNewDoc(BAD_CAST "1.0"), [](xmlDoc *doc) { xmlFreeDoc(doc); });
    if (doc == nullptr) {
        LOG_ERROR("Failed to initialize the xmlDoc.");
        return false;
    }
    xmlNode *rootNode = xmlNewNode(NULL, BAD_CAST "preferences");
    if (rootNode == nullptr) {
        LOG_ERROR("The xmlDoc failed to initialize the root node.");
        return false;
    }
    xmlNewProp(rootNode, BAD_CAST "version", BAD_CAST "1.0");

    // set root node
    xmlDocSetRootElement(doc.get(), rootNode);

    // set children node
    for (Element element : settings) {
        xmlNode *node = CreateElementNode(element);
        if (node == nullptr) {
            LOG_ERROR("The xmlDoc failed to initialize the element node.");
            return false;
        }
        if (xmlAddChild(rootNode, node) == nullptr) {
            /* free node in case of error */
            LOG_ERROR("The xmlDoc failed to add the child node.");
            xmlFreeNode(node);
            return false;
        }
    }

    /* 1: formatting spaces are added. */
    bool result = XmlSaveFormatFileEnc(fileName, bundleName, doc.get());
    return result;
}

/* static */
xmlNode *CreateElementNode(Element &element)
{
    if ((element.tag_.compare("int") == 0) || (element.tag_.compare("long") == 0)
        || (element.tag_.compare("float") == 0) || (element.tag_.compare("bool") == 0)
        || (element.tag_.compare("double") == 0)) {
        return CreatePrimitiveNode(element);
    }

    if (element.tag_.compare("string") == 0 || element.tag_.compare("uint8Array") == 0
        || element.tag_.compare("object") == 0) {
        return CreateStringNode(element);
    }

    if ((element.tag_.compare("doubleArray") == 0) || (element.tag_.compare("stringArray") == 0)
        || (element.tag_.compare("boolArray") == 0) || (element.tag_.compare("BigInt") == 0)) {
        return CreateArrayNode(element);
    }

    LOG_ERROR("An unsupported element type was encountered in parsing = %{public}s.", element.tag_.c_str());
    return nullptr;
}

/* static */
xmlNode *CreatePrimitiveNode(Element &element)
{
    xmlNode *node = xmlNewNode(NULL, BAD_CAST element.tag_.c_str());
    if (node == nullptr) {
        LOG_ERROR("The xmlDoc failed to initialize the primitive element node.");
        return nullptr;
    }
    if (!element.key_.empty()) {
        const char *key = element.key_.c_str();
        xmlNewProp(node, BAD_CAST "key", BAD_CAST key);
    }

    const char *value = element.value_.c_str();
    xmlNewProp(node, BAD_CAST "value", BAD_CAST value);
    return node;
}

xmlNode *CreateStringNode(Element &element)
{
    xmlNode *node = xmlNewNode(NULL, BAD_CAST element.tag_.c_str());
    if (node == nullptr) {
        LOG_ERROR("The xmlDoc failed to initialize the string element node.");
        return nullptr;
    }

    if (!element.key_.empty()) {
        const char *key = element.key_.c_str();
        xmlNewProp(node, BAD_CAST "key", BAD_CAST key);
    }

    const char *value = element.value_.c_str();
    xmlNodePtr text = xmlNewText(BAD_CAST value);
    if (xmlAddChild(node, text) == nullptr) {
        xmlFreeNode(text);
    }
    return node;
}

xmlNode *CreateArrayNode(Element &element)
{
    xmlNode *node = xmlNewNode(NULL, BAD_CAST element.tag_.c_str());
    if (node == nullptr) {
        LOG_ERROR("The xmlDoc failed to initialize the array element node.");
        return nullptr;
    }

    const char *key = element.key_.c_str();
    xmlNewProp(node, BAD_CAST "key", BAD_CAST key);

    if (element.children_.empty()) {
        return node;
    }
    Element flag = element.children_[0];
    if ((flag.tag_.compare("bool") == 0) || (flag.tag_.compare("double") == 0) ||
        (flag.tag_.compare("uint64_t") == 0)) {
        for (Element &child : element.children_) {
            xmlNode *childNode = CreatePrimitiveNode(child);
            if (childNode == nullptr) {
                continue;
            }
            if (xmlAddChild(node, childNode) == nullptr) {
                xmlFreeNode(childNode);
            }
        }
    } else if (flag.tag_.compare("string") == 0) {
        for (Element child : element.children_) {
            xmlNode *childNode = CreateStringNode(child);
            if (childNode == nullptr) {
                continue;
            }
            if (xmlAddChild(node, childNode) == nullptr) {
                xmlFreeNode(childNode);
            }
        }
    }
    return node;
}

void PreferencesXmlUtils::LimitXmlPermission(const std::string &fileName)
{
    /* clear execute permission of owner, clear execute permission of group, clear all permission of group. */
    struct stat fileStat = { 0 };
    if (stat(fileName.c_str(), &fileStat) != 0) {
        LOG_ERROR("Failed to obtain stat of file, errno:%{public}d.", errno);
        return;
    }
    if ((fileStat.st_mode & (S_IXUSR | S_IXGRP | S_IRWXO)) != 0) {
        int result = chmod(fileName.c_str(), fileStat.st_mode & (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP));
        if (result != 0) {
            LOG_ERROR("Failed to chmod file, errno:%{public}d.", errno);
        }
    }
}

} // End of namespace NativePreferences
} // End of namespace OHOS