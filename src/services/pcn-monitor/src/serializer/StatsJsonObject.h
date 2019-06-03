/**
* monitor API generated from monitor.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* StatsJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"


namespace polycube {
namespace service {
namespace model {


/// <summary>
///
/// </summary>
class  StatsJsonObject : public JsonObjectBase {
public:
  StatsJsonObject();
  StatsJsonObject(const nlohmann::json &json);
  ~StatsJsonObject() final = default;
  nlohmann::json toJson() const final;


  /// <summary>
  /// TCP attempt fails
  /// </summary>
  uint64_t getTcpattemptfails() const;
  void setTcpattemptfails(uint64_t value);
  bool tcpattemptfailsIsSet() const;
  void unsetTcpattemptfails();

  /// <summary>
  /// TCP sent with RST flag
  /// </summary>
  uint64_t getTcpoutrsts() const;
  void setTcpoutrsts(uint64_t value);
  bool tcpoutrstsIsSet() const;
  void unsetTcpoutrsts();

  /// <summary>
  /// pkts delivered to application over total number
  /// </summary>
  uint64_t getDeliverratio() const;
  void setDeliverratio(uint64_t value);
  bool deliverratioIsSet() const;
  void unsetDeliverratio();

  /// <summary>
  /// pkts request to send over received pkts
  /// </summary>
  uint64_t getResponseratio() const;
  void setResponseratio(uint64_t value);
  bool responseratioIsSet() const;
  void unsetResponseratio();

  /// <summary>
  /// last update (time from epoch in milliseconds)
  /// </summary>
  uint64_t getLastupdate() const;
  void setLastupdate(uint64_t value);
  bool lastupdateIsSet() const;
  void unsetLastupdate();

private:
  uint64_t m_tcpattemptfails;
  bool m_tcpattemptfailsIsSet;
  uint64_t m_tcpoutrsts;
  bool m_tcpoutrstsIsSet;
  uint64_t m_deliverratio;
  bool m_deliverratioIsSet;
  uint64_t m_responseratio;
  bool m_responseratioIsSet;
  uint64_t m_lastupdate;
  bool m_lastupdateIsSet;
};

}
}
}

