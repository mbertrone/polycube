/**
* iptables API
* iptables API generated from iptables.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "ChainInsertInputJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

ChainInsertInputJsonObject::ChainInsertInputJsonObject() {

  m_idIsSet = false;

  m_inIfaceIsSet = false;

  m_outIfaceIsSet = false;

  m_srcIsSet = false;

  m_dstIsSet = false;

  m_l4protoIsSet = false;

  m_sportIsSet = false;

  m_dportIsSet = false;

  m_tcpflagsIsSet = false;

  m_conntrackIsSet = false;

  m_actionIsSet = false;
}

ChainInsertInputJsonObject::~ChainInsertInputJsonObject() {}

void ChainInsertInputJsonObject::validateKeys() {

}

void ChainInsertInputJsonObject::validateMandatoryFields() {

}

void ChainInsertInputJsonObject::validateParams() {

}

nlohmann::json ChainInsertInputJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  if (m_idIsSet) {
    val["id"] = m_id;
  }

  if (m_inIfaceIsSet) {
    val["in-iface"] = m_inIface;
  }

  if (m_outIfaceIsSet) {
    val["out-iface"] = m_outIface;
  }

  if (m_srcIsSet) {
    val["src"] = m_src;
  }

  if (m_dstIsSet) {
    val["dst"] = m_dst;
  }

  if (m_l4protoIsSet) {
    val["l4proto"] = m_l4proto;
  }

  if (m_sportIsSet) {
    val["sport"] = m_sport;
  }

  if (m_dportIsSet) {
    val["dport"] = m_dport;
  }

  if (m_tcpflagsIsSet) {
    val["tcpflags"] = m_tcpflags;
  }

  if (m_conntrackIsSet) {
    val["conntrack"] = ConntrackstatusEnum_to_string(m_conntrack);
  }

  if (m_actionIsSet) {
    val["action"] = ActionEnum_to_string(m_action);
  }


  return val;
}

void ChainInsertInputJsonObject::fromJson(nlohmann::json& val) {
  for(nlohmann::json::iterator it = val.begin(); it != val.end(); ++it) {
    std::string key = it.key();
    bool found = (std::find(allowedParameters_.begin(), allowedParameters_.end(), key) != allowedParameters_.end());
    if (!found) {
      throw std::runtime_error(key + " is not a valid parameter");
      return;
    }
  }

  if (val.find("id") != val.end()) {
    setId(val.at("id"));
  }

  if (val.find("in-iface") != val.end()) {
    setInIface(val.at("in-iface"));
  }

  if (val.find("out-iface") != val.end()) {
    setOutIface(val.at("out-iface"));
  }

  if (val.find("src") != val.end()) {
    setSrc(val.at("src"));
  }

  if (val.find("dst") != val.end()) {
    setDst(val.at("dst"));
  }

  if (val.find("l4proto") != val.end()) {
    setL4proto(val.at("l4proto"));
  }

  if (val.find("sport") != val.end()) {
    setSport(val.at("sport"));
  }

  if (val.find("dport") != val.end()) {
    setDport(val.at("dport"));
  }

  if (val.find("tcpflags") != val.end()) {
    setTcpflags(val.at("tcpflags"));
  }

  if (val.find("conntrack") != val.end()) {
    setConntrack(string_to_ConntrackstatusEnum(val.at("conntrack")));
  }

  if (val.find("action") != val.end()) {
    setAction(string_to_ActionEnum(val.at("action")));
  }
}

nlohmann::json ChainInsertInputJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

nlohmann::json ChainInsertInputJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["id"]["name"] = "id";
  val["id"]["type"] = "leaf"; // Suppose that type is leaf
  val["id"]["simpletype"] = "integer";
  val["id"]["description"] = R"POLYCUBE()POLYCUBE";
  val["id"]["example"] = R"POLYCUBE()POLYCUBE";
  val["in-iface"]["name"] = "in-iface";
  val["in-iface"]["type"] = "leaf"; // Suppose that type is leaf
  val["in-iface"]["simpletype"] = "string";
  val["in-iface"]["description"] = R"POLYCUBE(Name of the interface via which the packet is received)POLYCUBE";
  val["in-iface"]["example"] = R"POLYCUBE(eth0)POLYCUBE";
  val["out-iface"]["name"] = "out-iface";
  val["out-iface"]["type"] = "leaf"; // Suppose that type is leaf
  val["out-iface"]["simpletype"] = "string";
  val["out-iface"]["description"] = R"POLYCUBE(Name of the interface via which the packet is going to be sent)POLYCUBE";
  val["out-iface"]["example"] = R"POLYCUBE(eth1)POLYCUBE";
  val["src"]["name"] = "src";
  val["src"]["type"] = "leaf"; // Suppose that type is leaf
  val["src"]["simpletype"] = "string";
  val["src"]["description"] = R"POLYCUBE(Source IP Address.)POLYCUBE";
  val["src"]["example"] = R"POLYCUBE(10.0.0.1/24)POLYCUBE";
  val["dst"]["name"] = "dst";
  val["dst"]["type"] = "leaf"; // Suppose that type is leaf
  val["dst"]["simpletype"] = "string";
  val["dst"]["description"] = R"POLYCUBE(Destination IP Address.)POLYCUBE";
  val["dst"]["example"] = R"POLYCUBE(10.0.0.2/24)POLYCUBE";
  val["l4proto"]["name"] = "l4proto";
  val["l4proto"]["type"] = "leaf"; // Suppose that type is leaf
  val["l4proto"]["simpletype"] = "string";
  val["l4proto"]["description"] = R"POLYCUBE(Level 4 Protocol.)POLYCUBE";
  val["l4proto"]["example"] = R"POLYCUBE()POLYCUBE";
  val["sport"]["name"] = "sport";
  val["sport"]["type"] = "leaf"; // Suppose that type is leaf
  val["sport"]["simpletype"] = "integer";
  val["sport"]["description"] = R"POLYCUBE(Source L4 Port)POLYCUBE";
  val["sport"]["example"] = R"POLYCUBE()POLYCUBE";
  val["dport"]["name"] = "dport";
  val["dport"]["type"] = "leaf"; // Suppose that type is leaf
  val["dport"]["simpletype"] = "integer";
  val["dport"]["description"] = R"POLYCUBE(Destination L4 Port)POLYCUBE";
  val["dport"]["example"] = R"POLYCUBE()POLYCUBE";
  val["tcpflags"]["name"] = "tcpflags";
  val["tcpflags"]["type"] = "leaf"; // Suppose that type is leaf
  val["tcpflags"]["simpletype"] = "string";
  val["tcpflags"]["description"] = R"POLYCUBE(TCP flags. Allowed values: SYN, FIN, ACK, RST, PSH, URG, CWR, ECE. ! means set to 0.)POLYCUBE";
  val["tcpflags"]["example"] = R"POLYCUBE(!FIN,SYN,!RST,!ACK)POLYCUBE";
  val["conntrack"]["name"] = "conntrack";
  val["conntrack"]["type"] = "leaf"; // Suppose that type is leaf
  val["conntrack"]["simpletype"] = "string";
  val["conntrack"]["description"] = R"POLYCUBE(Connection status (NEW, ESTABLISHED, RELATED, INVALID))POLYCUBE";
  val["conntrack"]["example"] = R"POLYCUBE()POLYCUBE";
  val["action"]["name"] = "action";
  val["action"]["type"] = "leaf"; // Suppose that type is leaf
  val["action"]["simpletype"] = "string";
  val["action"]["description"] = R"POLYCUBE(Action if the rule matches. Default is DROP.)POLYCUBE";
  val["action"]["example"] = R"POLYCUBE(DROP, ACCEPT, LOG)POLYCUBE";

  return val;
}

nlohmann::json ChainInsertInputJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["id"]["name"] = "id";
  val["id"]["simpletype"] = "integer";
  val["id"]["description"] = R"POLYCUBE()POLYCUBE";
  val["id"]["example"] = R"POLYCUBE()POLYCUBE";
  val["in-iface"]["name"] = "in-iface";
  val["in-iface"]["simpletype"] = "string";
  val["in-iface"]["description"] = R"POLYCUBE(Name of the interface via which the packet is received)POLYCUBE";
  val["in-iface"]["example"] = R"POLYCUBE(eth0)POLYCUBE";
  val["out-iface"]["name"] = "out-iface";
  val["out-iface"]["simpletype"] = "string";
  val["out-iface"]["description"] = R"POLYCUBE(Name of the interface via which the packet is going to be sent)POLYCUBE";
  val["out-iface"]["example"] = R"POLYCUBE(eth1)POLYCUBE";
  val["src"]["name"] = "src";
  val["src"]["simpletype"] = "string";
  val["src"]["description"] = R"POLYCUBE(Source IP Address.)POLYCUBE";
  val["src"]["example"] = R"POLYCUBE(10.0.0.1/24)POLYCUBE";
  val["dst"]["name"] = "dst";
  val["dst"]["simpletype"] = "string";
  val["dst"]["description"] = R"POLYCUBE(Destination IP Address.)POLYCUBE";
  val["dst"]["example"] = R"POLYCUBE(10.0.0.2/24)POLYCUBE";
  val["l4proto"]["name"] = "l4proto";
  val["l4proto"]["simpletype"] = "string";
  val["l4proto"]["description"] = R"POLYCUBE(Level 4 Protocol.)POLYCUBE";
  val["l4proto"]["example"] = R"POLYCUBE()POLYCUBE";
  val["sport"]["name"] = "sport";
  val["sport"]["simpletype"] = "integer";
  val["sport"]["description"] = R"POLYCUBE(Source L4 Port)POLYCUBE";
  val["sport"]["example"] = R"POLYCUBE()POLYCUBE";
  val["dport"]["name"] = "dport";
  val["dport"]["simpletype"] = "integer";
  val["dport"]["description"] = R"POLYCUBE(Destination L4 Port)POLYCUBE";
  val["dport"]["example"] = R"POLYCUBE()POLYCUBE";
  val["tcpflags"]["name"] = "tcpflags";
  val["tcpflags"]["simpletype"] = "string";
  val["tcpflags"]["description"] = R"POLYCUBE(TCP flags. Allowed values: SYN, FIN, ACK, RST, PSH, URG, CWR, ECE. ! means set to 0.)POLYCUBE";
  val["tcpflags"]["example"] = R"POLYCUBE(!FIN,SYN,!RST,!ACK)POLYCUBE";
  val["conntrack"]["name"] = "conntrack";
  val["conntrack"]["simpletype"] = "string";
  val["conntrack"]["description"] = R"POLYCUBE(Connection status (NEW, ESTABLISHED, RELATED, INVALID))POLYCUBE";
  val["conntrack"]["example"] = R"POLYCUBE()POLYCUBE";
  val["action"]["name"] = "action";
  val["action"]["simpletype"] = "string";
  val["action"]["description"] = R"POLYCUBE(Action if the rule matches. Default is DROP.)POLYCUBE";
  val["action"]["example"] = R"POLYCUBE(DROP, ACCEPT, LOG)POLYCUBE";

  return val;
}

nlohmann::json ChainInsertInputJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

std::vector<std::string> ChainInsertInputJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

uint32_t ChainInsertInputJsonObject::getId() const {
  return m_id;
}

void ChainInsertInputJsonObject::setId(uint32_t value) {
  m_id = value;
  m_idIsSet = true;
}

bool ChainInsertInputJsonObject::idIsSet() const {
  return m_idIsSet;
}

void ChainInsertInputJsonObject::unsetId() {
  m_idIsSet = false;
}



std::string ChainInsertInputJsonObject::getInIface() const {
  return m_inIface;
}

void ChainInsertInputJsonObject::setInIface(std::string value) {
  m_inIface = value;
  m_inIfaceIsSet = true;
}

bool ChainInsertInputJsonObject::inIfaceIsSet() const {
  return m_inIfaceIsSet;
}

void ChainInsertInputJsonObject::unsetInIface() {
  m_inIfaceIsSet = false;
}



std::string ChainInsertInputJsonObject::getOutIface() const {
  return m_outIface;
}

void ChainInsertInputJsonObject::setOutIface(std::string value) {
  m_outIface = value;
  m_outIfaceIsSet = true;
}

bool ChainInsertInputJsonObject::outIfaceIsSet() const {
  return m_outIfaceIsSet;
}

void ChainInsertInputJsonObject::unsetOutIface() {
  m_outIfaceIsSet = false;
}



std::string ChainInsertInputJsonObject::getSrc() const {
  return m_src;
}

void ChainInsertInputJsonObject::setSrc(std::string value) {
  m_src = value;
  m_srcIsSet = true;
}

bool ChainInsertInputJsonObject::srcIsSet() const {
  return m_srcIsSet;
}

void ChainInsertInputJsonObject::unsetSrc() {
  m_srcIsSet = false;
}



std::string ChainInsertInputJsonObject::getDst() const {
  return m_dst;
}

void ChainInsertInputJsonObject::setDst(std::string value) {
  m_dst = value;
  m_dstIsSet = true;
}

bool ChainInsertInputJsonObject::dstIsSet() const {
  return m_dstIsSet;
}

void ChainInsertInputJsonObject::unsetDst() {
  m_dstIsSet = false;
}



std::string ChainInsertInputJsonObject::getL4proto() const {
  return m_l4proto;
}

void ChainInsertInputJsonObject::setL4proto(std::string value) {
  m_l4proto = value;
  m_l4protoIsSet = true;
}

bool ChainInsertInputJsonObject::l4protoIsSet() const {
  return m_l4protoIsSet;
}

void ChainInsertInputJsonObject::unsetL4proto() {
  m_l4protoIsSet = false;
}



uint16_t ChainInsertInputJsonObject::getSport() const {
  return m_sport;
}

void ChainInsertInputJsonObject::setSport(uint16_t value) {
  m_sport = value;
  m_sportIsSet = true;
}

bool ChainInsertInputJsonObject::sportIsSet() const {
  return m_sportIsSet;
}

void ChainInsertInputJsonObject::unsetSport() {
  m_sportIsSet = false;
}



uint16_t ChainInsertInputJsonObject::getDport() const {
  return m_dport;
}

void ChainInsertInputJsonObject::setDport(uint16_t value) {
  m_dport = value;
  m_dportIsSet = true;
}

bool ChainInsertInputJsonObject::dportIsSet() const {
  return m_dportIsSet;
}

void ChainInsertInputJsonObject::unsetDport() {
  m_dportIsSet = false;
}



std::string ChainInsertInputJsonObject::getTcpflags() const {
  return m_tcpflags;
}

void ChainInsertInputJsonObject::setTcpflags(std::string value) {
  m_tcpflags = value;
  m_tcpflagsIsSet = true;
}

bool ChainInsertInputJsonObject::tcpflagsIsSet() const {
  return m_tcpflagsIsSet;
}

void ChainInsertInputJsonObject::unsetTcpflags() {
  m_tcpflagsIsSet = false;
}



ConntrackstatusEnum ChainInsertInputJsonObject::getConntrack() const {
  return m_conntrack;
}

void ChainInsertInputJsonObject::setConntrack(ConntrackstatusEnum value) {
  m_conntrack = value;
  m_conntrackIsSet = true;
}

bool ChainInsertInputJsonObject::conntrackIsSet() const {
  return m_conntrackIsSet;
}

void ChainInsertInputJsonObject::unsetConntrack() {
  m_conntrackIsSet = false;
}

std::string ChainInsertInputJsonObject::ConntrackstatusEnum_to_string(const ConntrackstatusEnum &value){
  switch(value){
    case ConntrackstatusEnum::NEW:
      return std::string("new");
    case ConntrackstatusEnum::ESTABLISHED:
      return std::string("established");
    case ConntrackstatusEnum::RELATED:
      return std::string("related");
    case ConntrackstatusEnum::INVALID:
      return std::string("invalid");
    default:
      throw std::runtime_error("Bad ChainInsertInput conntrack");
  }
}

ConntrackstatusEnum ChainInsertInputJsonObject::string_to_ConntrackstatusEnum(const std::string &str){
  if (JsonObjectBase::iequals("new", str))
    return ConntrackstatusEnum::NEW;
  if (JsonObjectBase::iequals("established", str))
    return ConntrackstatusEnum::ESTABLISHED;
  if (JsonObjectBase::iequals("related", str))
    return ConntrackstatusEnum::RELATED;
  if (JsonObjectBase::iequals("invalid", str))
    return ConntrackstatusEnum::INVALID;
  throw std::runtime_error("ChainInsertInput conntrack is invalid");
}


ActionEnum ChainInsertInputJsonObject::getAction() const {
  return m_action;
}

void ChainInsertInputJsonObject::setAction(ActionEnum value) {
  m_action = value;
  m_actionIsSet = true;
}

bool ChainInsertInputJsonObject::actionIsSet() const {
  return m_actionIsSet;
}

void ChainInsertInputJsonObject::unsetAction() {
  m_actionIsSet = false;
}

std::string ChainInsertInputJsonObject::ActionEnum_to_string(const ActionEnum &value){
  switch(value){
    case ActionEnum::DROP:
      return std::string("drop");
    case ActionEnum::LOG:
      return std::string("log");
    case ActionEnum::ACCEPT:
      return std::string("accept");
    default:
      throw std::runtime_error("Bad ChainInsertInput action");
  }
}

ActionEnum ChainInsertInputJsonObject::string_to_ActionEnum(const std::string &str){
  if (JsonObjectBase::iequals("drop", str))
    return ActionEnum::DROP;
  if (JsonObjectBase::iequals("log", str))
    return ActionEnum::LOG;
  if (JsonObjectBase::iequals("accept", str))
    return ActionEnum::ACCEPT;
  throw std::runtime_error("ChainInsertInput action is invalid");
}



}
}
}
}

