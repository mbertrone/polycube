/**
* monitor API generated from monitor.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* MonitorJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"

#include "StatsJsonObject.h"
#include "polycube/services/cube.h"

namespace polycube {
namespace service {
namespace model {


/// <summary>
///
/// </summary>
class  MonitorJsonObject : public JsonObjectBase {
public:
  MonitorJsonObject();
  MonitorJsonObject(const nlohmann::json &json);
  ~MonitorJsonObject() final = default;
  nlohmann::json toJson() const final;


  /// <summary>
  /// Name of the monitor service
  /// </summary>
  std::string getName() const;
  void setName(std::string value);
  bool nameIsSet() const;

  /// <summary>
  ///
  /// </summary>
  StatsJsonObject getStats() const;
  void setStats(StatsJsonObject value);
  bool statsIsSet() const;
  void unsetStats();

private:
  std::string m_name;
  bool m_nameIsSet;
  StatsJsonObject m_stats;
  bool m_statsIsSet;
};

}
}
}
