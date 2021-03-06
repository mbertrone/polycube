/**
* simpleforwarder API
* Simple Forwarder Base Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "ActionsJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

ActionsJsonObject::ActionsJsonObject() {

  m_inportIsSet = false;

  m_actionIsSet = false;

  m_outportIsSet = false;
}

ActionsJsonObject::~ActionsJsonObject() {}

void ActionsJsonObject::validateKeys() {

  if (!m_inportIsSet) {
    throw std::runtime_error("Variable inport is required");
  }
}

void ActionsJsonObject::validateMandatoryFields() {

  if (!m_actionIsSet) {
    throw std::runtime_error("Variable action is required");
  }
}

void ActionsJsonObject::validateParams() {

}

nlohmann::json ActionsJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  if (m_inportIsSet) {
    val["inport"] = m_inport;
  }

  val["action"] = ActionsActionEnum_to_string(m_action);
  if (m_outportIsSet) {
    val["outport"] = m_outport;
  }


  return val;
}

void ActionsJsonObject::fromJson(nlohmann::json& val) {
  for(nlohmann::json::iterator it = val.begin(); it != val.end(); ++it) {
    std::string key = it.key();
    bool found = (std::find(allowedParameters_.begin(), allowedParameters_.end(), key) != allowedParameters_.end());
    if (!found) {
      throw std::runtime_error(key + " is not a valid parameter");
      return;
    }
  }

  if (val.find("inport") != val.end()) {
    setInport(val.at("inport"));
  }

  if (val.find("action") != val.end()) {
    setAction(string_to_ActionsActionEnum(val.at("action")));
  }

  if (val.find("outport") != val.end()) {
    setOutport(val.at("outport"));
  }
}

nlohmann::json ActionsJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();

  val["inport"]["name"] = "inport";
  val["inport"]["type"] = "key";
  val["inport"]["simpletype"] = "string";
  val["inport"]["description"] = R"POLYCUBE(Ingress port)POLYCUBE";
  val["inport"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json ActionsJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["action"]["name"] = "action";
  val["action"]["type"] = "leaf"; // Suppose that type is leaf
  val["action"]["simpletype"] = "string";
  val["action"]["description"] = R"POLYCUBE(Action associated to the current table entry (i.e., DROP, SLOWPATH, or FORWARD; default: DROP))POLYCUBE";
  val["action"]["example"] = R"POLYCUBE()POLYCUBE";
  val["outport"]["name"] = "outport";
  val["outport"]["type"] = "leaf"; // Suppose that type is leaf
  val["outport"]["simpletype"] = "string";
  val["outport"]["description"] = R"POLYCUBE(Output port (used only when action is FORWARD))POLYCUBE";
  val["outport"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json ActionsJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["action"]["name"] = "action";
  val["action"]["simpletype"] = "string";
  val["action"]["description"] = R"POLYCUBE(Action associated to the current table entry (i.e., DROP, SLOWPATH, or FORWARD; default: DROP))POLYCUBE";
  val["action"]["example"] = R"POLYCUBE()POLYCUBE";
  val["outport"]["name"] = "outport";
  val["outport"]["simpletype"] = "string";
  val["outport"]["description"] = R"POLYCUBE(Output port (used only when action is FORWARD))POLYCUBE";
  val["outport"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json ActionsJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

std::vector<std::string> ActionsJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

std::string ActionsJsonObject::getInport() const {
  return m_inport;
}

void ActionsJsonObject::setInport(std::string value) {
  m_inport = value;
  m_inportIsSet = true;
}

bool ActionsJsonObject::inportIsSet() const {
  return m_inportIsSet;
}

void ActionsJsonObject::unsetInport() {
  m_inportIsSet = false;
}



ActionsActionEnum ActionsJsonObject::getAction() const {
  return m_action;
}

void ActionsJsonObject::setAction(ActionsActionEnum value) {
  m_action = value;
  m_actionIsSet = true;
}

bool ActionsJsonObject::actionIsSet() const {
  return m_actionIsSet;
}

void ActionsJsonObject::unsetAction() {
  m_actionIsSet = false;
}

std::string ActionsJsonObject::ActionsActionEnum_to_string(const ActionsActionEnum &value){
  switch(value){
    case ActionsActionEnum::DROP:
      return std::string("drop");
    case ActionsActionEnum::SLOWPATH:
      return std::string("slowpath");
    case ActionsActionEnum::FORWARD:
      return std::string("forward");
    default:
      throw std::runtime_error("Bad Actions action");
  }
}

ActionsActionEnum ActionsJsonObject::string_to_ActionsActionEnum(const std::string &str){
  if (JsonObjectBase::iequals("drop", str))
    return ActionsActionEnum::DROP;
  if (JsonObjectBase::iequals("slowpath", str))
    return ActionsActionEnum::SLOWPATH;
  if (JsonObjectBase::iequals("forward", str))
    return ActionsActionEnum::FORWARD;
  throw std::runtime_error("Actions action is invalid");
}


std::string ActionsJsonObject::getOutport() const {
  return m_outport;
}

void ActionsJsonObject::setOutport(std::string value) {
  m_outport = value;
  m_outportIsSet = true;
}

bool ActionsJsonObject::outportIsSet() const {
  return m_outportIsSet;
}

void ActionsJsonObject::unsetOutport() {
  m_outportIsSet = false;
}




}
}
}
}

