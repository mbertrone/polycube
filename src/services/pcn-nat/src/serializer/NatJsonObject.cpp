/**
* nat API
* NAT Service
*
* OpenAPI spec version: 1.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "NatJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

NatJsonObject::NatJsonObject() {

  m_nameIsSet = false;

  m_uuidIsSet = false;

  m_type = CubeType::TC;
  m_typeIsSet = false;

  m_loglevel = NatLoglevelEnum::INFO;
  m_loglevelIsSet = false;

  m_ruleIsSet = false;

  m_nattingTableIsSet = false;
}

NatJsonObject::~NatJsonObject() {}

void NatJsonObject::validateKeys() {

  if (!m_nameIsSet) {
    throw std::runtime_error("Variable name is required");
  }
}

void NatJsonObject::validateMandatoryFields() {

}

void NatJsonObject::validateParams() {

  if (m_uuidIsSet) {
    std::string patter_value = R"PATTERN([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})PATTERN";
    std::regex e (patter_value);
    if (!std::regex_match(m_uuid, e))
      throw std::runtime_error("Variable uuid has not a valid format");
  }
}

nlohmann::json NatJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  if (m_nameIsSet) {
    val["name"] = m_name;
  }

  if (m_uuidIsSet) {
    val["uuid"] = m_uuid;
  }

  if (m_typeIsSet) {
    val["type"] = CubeType_to_string(m_type);
  }

  if (m_loglevelIsSet) {
    val["loglevel"] = NatLoglevelEnum_to_string(m_loglevel);
  }

  if (m_ruleIsSet) {
    val["rule"] = JsonObjectBase::toJson(m_rule);
  }
  {
    nlohmann::json jsonArray;
    for (auto& item : m_nattingTable) {
      jsonArray.push_back(JsonObjectBase::toJson(item));
    }

    if (jsonArray.size() > 0) {
      val["natting-table"] = jsonArray;
    }
  }

  return val;
}

void NatJsonObject::fromJson(nlohmann::json& val) {
  for(nlohmann::json::iterator it = val.begin(); it != val.end(); ++it) {
    std::string key = it.key();
    bool found = (std::find(allowedParameters_.begin(), allowedParameters_.end(), key) != allowedParameters_.end());
    if (!found) {
      throw std::runtime_error(key + " is not a valid parameter");
      return;
    }
  }

  if (val.find("name") != val.end()) {
    setName(val.at("name"));
  }

  if (val.find("uuid") != val.end()) {
    setUuid(val.at("uuid"));
  }

  if (val.find("type") != val.end()) {
    setType(string_to_CubeType(val.at("type")));
  }

  if (val.find("loglevel") != val.end()) {
    setLoglevel(string_to_NatLoglevelEnum(val.at("loglevel")));
  }


  if (val.find("rule") != val.end()) {


    if (!val["rule"].is_null()) {
      RuleJsonObject newItem;
      newItem.fromJson(val["rule"]);
      setRule(newItem);
    }
  }

  m_nattingTable.clear();
  for (auto& item : val["natting-table"]) {

    NattingTableJsonObject newItem;
    newItem.fromJson(item);
    m_nattingTable.push_back(newItem);
    m_nattingTableIsSet = true;
  }

}

nlohmann::json NatJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();

  val["name"]["name"] = "name";
  val["name"]["type"] = "key";
  val["name"]["simpletype"] = "string";
  val["name"]["description"] = R"POLYCUBE(Name of the nat service)POLYCUBE";
  val["name"]["example"] = R"POLYCUBE(nat1)POLYCUBE";

  return val;
}

nlohmann::json NatJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["uuid"]["name"] = "uuid";
  val["uuid"]["type"] = "leaf"; // Suppose that type is leaf
  val["uuid"]["simpletype"] = "string";
  val["uuid"]["description"] = R"POLYCUBE(UUID of the Cube)POLYCUBE";
  val["uuid"]["example"] = R"POLYCUBE()POLYCUBE";
  val["type"]["name"] = "type";
  val["type"]["type"] = "leaf"; // Suppose that type is leaf
  val["type"]["simpletype"] = "string";
  val["type"]["description"] = R"POLYCUBE(Type of the Cube (TC, XDP_SKB, XDP_DRV))POLYCUBE";
  val["type"]["example"] = R"POLYCUBE(TC)POLYCUBE";
  val["loglevel"]["name"] = "loglevel";
  val["loglevel"]["type"] = "leaf"; // Suppose that type is leaf
  val["loglevel"]["simpletype"] = "string";
  val["loglevel"]["description"] = R"POLYCUBE(Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE))POLYCUBE";
  val["loglevel"]["example"] = R"POLYCUBE(INFO)POLYCUBE";
  val["rule"]["name"] = "rule";
  val["rule"]["type"] = "leaf"; // Suppose that type is leaf
  val["rule"]["description"] = R"POLYCUBE()POLYCUBE";
  val["rule"]["example"] = R"POLYCUBE()POLYCUBE";
  val["natting-table"]["name"] = "natting-table";
  val["natting-table"]["type"] = "leaf"; // Suppose that type is leaf
  val["natting-table"]["type"] = "list";
  val["natting-table"]["description"] = R"POLYCUBE()POLYCUBE";
  val["natting-table"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json NatJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["loglevel"]["name"] = "loglevel";
  val["loglevel"]["simpletype"] = "string";
  val["loglevel"]["description"] = R"POLYCUBE(Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE))POLYCUBE";
  val["loglevel"]["example"] = R"POLYCUBE(INFO)POLYCUBE";

  return val;
}

nlohmann::json NatJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();

  val["rule"]["name"] = "rule";
  val["rule"]["type"] = "complex";
  val["rule"]["description"] = R"POLYCUBE()POLYCUBE";
  val["rule"]["example"] = R"POLYCUBE()POLYCUBE";
  val["natting-table"]["name"] = "natting-table";
  val["natting-table"]["type"] = "list";
  val["natting-table"]["description"] = R"POLYCUBE()POLYCUBE";
  val["natting-table"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

std::vector<std::string> NatJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

std::string NatJsonObject::getName() const {
  return m_name;
}

void NatJsonObject::setName(std::string value) {
  m_name = value;
  m_nameIsSet = true;
}

bool NatJsonObject::nameIsSet() const {
  return m_nameIsSet;
}

void NatJsonObject::unsetName() {
  m_nameIsSet = false;
}



std::string NatJsonObject::getUuid() const {
  return m_uuid;
}

void NatJsonObject::setUuid(std::string value) {
  m_uuid = value;
  m_uuidIsSet = true;
}

bool NatJsonObject::uuidIsSet() const {
  return m_uuidIsSet;
}

void NatJsonObject::unsetUuid() {
  m_uuidIsSet = false;
}



CubeType NatJsonObject::getType() const {
  return m_type;
}

void NatJsonObject::setType(CubeType value) {
  m_type = value;
  m_typeIsSet = true;
}

bool NatJsonObject::typeIsSet() const {
  return m_typeIsSet;
}

void NatJsonObject::unsetType() {
  m_typeIsSet = false;
}

std::string NatJsonObject::CubeType_to_string(const CubeType &value){
  switch(value){
    case CubeType::TC:
      return std::string("TC");
    case CubeType::XDP_SKB:
      return std::string("XDP_SKB");
    case CubeType::XDP_DRV:
      return std::string("XDP_DRV");
    default:
      throw std::runtime_error("Bad Nat type");
  }
}

CubeType NatJsonObject::string_to_CubeType(const std::string &str){
  if (JsonObjectBase::iequals("TC", str))
    return CubeType::TC;
  if (JsonObjectBase::iequals("XDP_SKB", str))
    return CubeType::XDP_SKB;
  if (JsonObjectBase::iequals("XDP_DRV", str))
    return CubeType::XDP_DRV;
  throw std::runtime_error("Nat type is invalid");
}


NatLoglevelEnum NatJsonObject::getLoglevel() const {
  return m_loglevel;
}

void NatJsonObject::setLoglevel(NatLoglevelEnum value) {
  m_loglevel = value;
  m_loglevelIsSet = true;
}

bool NatJsonObject::loglevelIsSet() const {
  return m_loglevelIsSet;
}

void NatJsonObject::unsetLoglevel() {
  m_loglevelIsSet = false;
}

std::string NatJsonObject::NatLoglevelEnum_to_string(const NatLoglevelEnum &value){
  switch(value){
    case NatLoglevelEnum::TRACE:
      return std::string("trace");
    case NatLoglevelEnum::DEBUG:
      return std::string("debug");
    case NatLoglevelEnum::INFO:
      return std::string("info");
    case NatLoglevelEnum::WARN:
      return std::string("warn");
    case NatLoglevelEnum::ERR:
      return std::string("err");
    case NatLoglevelEnum::CRITICAL:
      return std::string("critical");
    case NatLoglevelEnum::OFF:
      return std::string("off");
    default:
      throw std::runtime_error("Bad Nat loglevel");
  }
}

NatLoglevelEnum NatJsonObject::string_to_NatLoglevelEnum(const std::string &str){
  if (JsonObjectBase::iequals("trace", str))
    return NatLoglevelEnum::TRACE;
  if (JsonObjectBase::iequals("debug", str))
    return NatLoglevelEnum::DEBUG;
  if (JsonObjectBase::iequals("info", str))
    return NatLoglevelEnum::INFO;
  if (JsonObjectBase::iequals("warn", str))
    return NatLoglevelEnum::WARN;
  if (JsonObjectBase::iequals("err", str))
    return NatLoglevelEnum::ERR;
  if (JsonObjectBase::iequals("critical", str))
    return NatLoglevelEnum::CRITICAL;
  if (JsonObjectBase::iequals("off", str))
    return NatLoglevelEnum::OFF;
  throw std::runtime_error("Nat loglevel is invalid");
}

  polycube::LogLevel NatJsonObject::getPolycubeLoglevel() const {
    switch(m_loglevel) {
      case NatLoglevelEnum::TRACE:
        return polycube::LogLevel::TRACE;
      case NatLoglevelEnum::DEBUG:
        return polycube::LogLevel::DEBUG;
      case NatLoglevelEnum::INFO:
        return polycube::LogLevel::INFO;
      case NatLoglevelEnum::WARN:
        return polycube::LogLevel::WARN;
      case NatLoglevelEnum::ERR:
        return polycube::LogLevel::ERR;
      case NatLoglevelEnum::CRITICAL:
        return polycube::LogLevel::CRITICAL;
      case NatLoglevelEnum::OFF:
        return polycube::LogLevel::OFF;
    }
  }

RuleJsonObject NatJsonObject::getRule() const {
  return m_rule;
}

void NatJsonObject::setRule(RuleJsonObject value) {
  m_rule = value;
  m_ruleIsSet = true;
}

bool NatJsonObject::ruleIsSet() const {
  return m_ruleIsSet;
}

void NatJsonObject::unsetRule() {
  m_ruleIsSet = false;
}



const std::vector<NattingTableJsonObject>& NatJsonObject::getNattingTable() const{
  return m_nattingTable;
}

void NatJsonObject::addNattingTable(NattingTableJsonObject value) {
  m_nattingTable.push_back(value);
}


bool NatJsonObject::nattingTableIsSet() const {
  return m_nattingTableIsSet;
}

void NatJsonObject::unsetNattingTable() {
  m_nattingTableIsSet = false;
}




}
}
}
}

