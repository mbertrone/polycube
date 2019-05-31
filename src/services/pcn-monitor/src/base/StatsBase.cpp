/**
* monitor API generated from monitor.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */


#include "StatsBase.h"
#include "../Monitor.h"


StatsBase::StatsBase(Monitor &parent)
    : parent_(parent) {}

StatsBase::~StatsBase() {}

void StatsBase::update(const StatsJsonObject &conf) {

}

StatsJsonObject StatsBase::toJsonObject() {
  StatsJsonObject conf;

  conf.setTcpattemptfails(getTcpattemptfails());
  conf.setTcpoutrsts(getTcpoutrsts());
  conf.setDeliverration(getDeliverration());
  conf.setResponseratio(getResponseratio());
  conf.setTimestamp(getTimestamp());

  return conf;
}

std::shared_ptr<spdlog::logger> StatsBase::logger() {
  return parent_.logger();
}

