/**
* monitor API generated from monitor.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */



#include "StatsJsonObject.h"
#include <regex>

namespace polycube {
namespace service {
namespace model {

StatsJsonObject::StatsJsonObject() {
  m_tcpattemptfailsIsSet = false;
  m_tcpoutrstsIsSet = false;
  m_deliverratioIsSet = false;
  m_responseratioIsSet = false;
  m_lastupdateIsSet = false;
}

StatsJsonObject::StatsJsonObject(const nlohmann::json &val) :
  JsonObjectBase(val) {
  m_tcpattemptfailsIsSet = false;
  m_tcpoutrstsIsSet = false;
  m_deliverratioIsSet = false;
  m_responseratioIsSet = false;
  m_lastupdateIsSet = false;


  if (val.count("tcpattemptfails")) {
    setTcpattemptfails(val.at("tcpattemptfails").get<uint64_t>());
  }

  if (val.count("tcpoutrsts")) {
    setTcpoutrsts(val.at("tcpoutrsts").get<uint64_t>());
  }

  if (val.count("deliverratio")) {
    setDeliverratio(val.at("deliverratio").get<uint64_t>());
  }

  if (val.count("responseratio")) {
    setResponseratio(val.at("responseratio").get<uint64_t>());
  }

  if (val.count("lastupdate")) {
    setLastupdate(val.at("lastupdate").get<uint64_t>());
  }
}

nlohmann::json StatsJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();
  if (!getBase().is_null()) {
    val.update(getBase());
  }

  if (m_tcpattemptfailsIsSet) {
    val["tcpattemptfails"] = m_tcpattemptfails;
  }

  if (m_tcpoutrstsIsSet) {
    val["tcpoutrsts"] = m_tcpoutrsts;
  }

  if (m_deliverratioIsSet) {
    val["deliverratio"] = m_deliverratio;
  }

  if (m_responseratioIsSet) {
    val["responseratio"] = m_responseratio;
  }

  if (m_lastupdateIsSet) {
    val["lastupdate"] = m_lastupdate;
  }

  return val;
}

uint64_t StatsJsonObject::getTcpattemptfails() const {
  return m_tcpattemptfails;
}

void StatsJsonObject::setTcpattemptfails(uint64_t value) {
  m_tcpattemptfails = value;
  m_tcpattemptfailsIsSet = true;
}

bool StatsJsonObject::tcpattemptfailsIsSet() const {
  return m_tcpattemptfailsIsSet;
}

void StatsJsonObject::unsetTcpattemptfails() {
  m_tcpattemptfailsIsSet = false;
}

uint64_t StatsJsonObject::getTcpoutrsts() const {
  return m_tcpoutrsts;
}

void StatsJsonObject::setTcpoutrsts(uint64_t value) {
  m_tcpoutrsts = value;
  m_tcpoutrstsIsSet = true;
}

bool StatsJsonObject::tcpoutrstsIsSet() const {
  return m_tcpoutrstsIsSet;
}

void StatsJsonObject::unsetTcpoutrsts() {
  m_tcpoutrstsIsSet = false;
}

uint64_t StatsJsonObject::getDeliverratio() const {
  return m_deliverratio;
}

void StatsJsonObject::setDeliverratio(uint64_t value) {
  m_deliverratio = value;
  m_deliverratioIsSet = true;
}

bool StatsJsonObject::deliverratioIsSet() const {
  return m_deliverratioIsSet;
}

void StatsJsonObject::unsetDeliverratio() {
  m_deliverratioIsSet = false;
}

uint64_t StatsJsonObject::getResponseratio() const {
  return m_responseratio;
}

void StatsJsonObject::setResponseratio(uint64_t value) {
  m_responseratio = value;
  m_responseratioIsSet = true;
}

bool StatsJsonObject::responseratioIsSet() const {
  return m_responseratioIsSet;
}

void StatsJsonObject::unsetResponseratio() {
  m_responseratioIsSet = false;
}

uint64_t StatsJsonObject::getLastupdate() const {
  return m_lastupdate;
}

void StatsJsonObject::setLastupdate(uint64_t value) {
  m_lastupdate = value;
  m_lastupdateIsSet = true;
}

bool StatsJsonObject::lastupdateIsSet() const {
  return m_lastupdateIsSet;
}

void StatsJsonObject::unsetLastupdate() {
  m_lastupdateIsSet = false;
}


}
}
}

