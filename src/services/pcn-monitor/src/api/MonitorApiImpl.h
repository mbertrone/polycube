/**
* monitor API generated from monitor.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* MonitorApiImpl.h
*
*
*/

#pragma once


#include <memory>
#include <map>
#include <mutex>
#include "../Monitor.h"

#include "MonitorJsonObject.h"
#include "StatsJsonObject.h"
#include <vector>

namespace polycube {
namespace service {
namespace api {

using namespace polycube::service::model;

namespace MonitorApiImpl {
  void create_monitor_by_id(const std::string &name, const MonitorJsonObject &value);
  void delete_monitor_by_id(const std::string &name);
  MonitorJsonObject read_monitor_by_id(const std::string &name);
  std::vector<MonitorJsonObject> read_monitor_list_by_id();
  StatsJsonObject read_monitor_stats_by_id(const std::string &name);
  uint64_t read_monitor_stats_deliverration_by_id(const std::string &name);
  uint64_t read_monitor_stats_responseratio_by_id(const std::string &name);
  uint64_t read_monitor_stats_tcpattemptfails_by_id(const std::string &name);
  uint64_t read_monitor_stats_tcpoutrsts_by_id(const std::string &name);
  uint64_t read_monitor_stats_timestamp_by_id(const std::string &name);
  void replace_monitor_by_id(const std::string &name, const MonitorJsonObject &value);
  void update_monitor_by_id(const std::string &name, const MonitorJsonObject &value);
  void update_monitor_list_by_id(const std::vector<MonitorJsonObject> &value);

  /* help related */
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_monitor_list_by_id_get_list();

}
}
}
}

