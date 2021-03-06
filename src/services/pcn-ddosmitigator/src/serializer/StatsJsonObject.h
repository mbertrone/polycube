/**
* ddosmitigator API
* DDoS Mitigator Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* StatsJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"


namespace io {
namespace swagger {
namespace server {
namespace model {


/// <summary>
///
/// </summary>
class  StatsJsonObject : public JsonObjectBase {
public:
  StatsJsonObject();
  virtual ~StatsJsonObject();

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  void validateKeys() override;
  void validateMandatoryFields() override;
  void validateParams() override;

  nlohmann::json toJson() const override;
  void fromJson(nlohmann::json& json) override;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// StatsJsonObject members

  /// <summary>
  /// Dropped Packets/s
  /// </summary>
  uint64_t getPps() const;
  void setPps(uint64_t value);
  bool ppsIsSet() const;
  void unsetPps();

  /// <summary>
  /// Total Dropped Packets
  /// </summary>
  uint64_t getPkts() const;
  void setPkts(uint64_t value);
  bool pktsIsSet() const;
  void unsetPkts();


protected:
  uint64_t m_pps;
  bool m_ppsIsSet;
  uint64_t m_pkts;
  bool m_pktsIsSet;

  std::vector<std::string> allowedParameters_{ "pps", "pkts" };
};

}
}
}
}

