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
#include "preferences_file_lock.h"
#include "preferences_file_operation.h"
#include "preferences_impl.h"
namespace OHOS {
namespace NativePreferences {
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

static bool RenameFromBackupFile(const std::string &fileName)
{
    std::string backupFileName = MakeFilePath(fileName, STR_BACKUP);
    if (!IsFileExist(backupFileName)) {
        LOG_DEBUG("the backup file does not exist.");
        return false;
    }
    if (std::rename(backupFileName.c_str(), fileName.c_str())) {
        LOG_ERROR("failed to restore backup errno %{public}d.", errno);
        return false;
    }
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

static xmlDoc *ReadFile(const std::string &fileName)
{
    return xmlReadFile(fileName.c_str(), "UTF-8", XML_PARSE_NOBLANKS);
}

static xmlDoc *XmlReadFile(const std::string &fileName, const std::string &dataGroupId)
{
    xmlDoc *doc = nullptr;
    PreferencesFileLock fileLock(MakeFilePath(fileName, STR_LOCK), dataGroupId);
    if (IsFileExist(fileName)) {
        doc = ReadFile(fileName);
        if (doc != nullptr) {
            return doc;
        }
        xmlErrorPtr xmlErr = xmlGetLastError();
        std::string errMessage = (xmlErr != nullptr) ? xmlErr->message : "null";
        LOG_ERROR("failed to read XML format file, error is %{public}s.", errMessage.c_str());
        if (!RenameToBrokenFile(fileName)) {
            return doc;
        }
    }
    if (RenameFromBackupFile(fileName)) {
        return ReadFile(fileName);
    }
    return nullptr;
}

/* static */
bool PreferencesXmlUtils::ReadSettingXml(
    const std::string &fileName, const std::string &dataGroupId, std::vector<Element> &settings)
{
    LOG_RECORD_FILE_NAME("Read setting xml start.");
    if (fileName.size() == 0) {
        LOG_ERROR("The length of the file name is 0.");
        return false;
    }
    auto doc = std::shared_ptr<xmlDoc>(XmlReadFile(fileName, dataGroupId), [](xmlDoc *doc) { xmlFreeDoc(doc); });
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

    /* free the document */
    LOG_RECORD_FILE_NAME("Read setting xml end.");
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

static bool SaveFormatFileEnc(const std::string &fileName, xmlDoc *doc)
{
    return xmlSaveFormatFileEnc(fileName.c_str(), doc, "UTF-8", 1) > 0;
}

bool XmlSaveFormatFileEnc(const std::string &fileName, const std::string &dataGroupId, xmlDoc *doc)
{
    PreferencesFileLock fileLock(MakeFilePath(fileName, STR_LOCK), dataGroupId);
    if (IsFileExist(fileName) && !RenameToBackupFile(fileName)) {
        return false;
    }

    if (!SaveFormatFileEnc(fileName, doc)) {
        xmlErrorPtr xmlErr = xmlGetLastError();
        std::string errMessage = (xmlErr != nullptr) ? xmlErr->message : "null";
        LOG_ERROR("failed to save XML format file, error is %{public}s.", errMessage.c_str());
        if (IsFileExist(fileName)) {
            RenameToBrokenFile(fileName);
        }
        RenameFromBackupFile(fileName);
        return false;
    }

    RemoveBackupFile(fileName);
    PreferencesXmlUtils::LimitXmlPermission(fileName);
    // make sure the file is written to disk.
    if (!Fsync(fileName)) {
        LOG_WARN("failed to write the file to the disk.");
    }
    LOG_DEBUG("successfully saved the XML format file");
    return true;
}

/* static */
bool PreferencesXmlUtils::WriteSettingXml(
    const std::string &fileName, const std::string &dataGroupId, const std::vector<Element> &settings)
{
    LOG_RECORD_FILE_NAME("Write setting xml start.");
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
    bool result = XmlSaveFormatFileEnc(fileName, dataGroupId, doc.get());
    LOG_RECORD_FILE_NAME("Write setting xml end.");
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