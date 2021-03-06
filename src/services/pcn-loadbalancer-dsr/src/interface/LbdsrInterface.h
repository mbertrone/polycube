/**
* lbdsr API
* LoadBalancer Direct Server Return Service
*
* OpenAPI spec version: 2.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* LbdsrInterface.h
*
*
*/

#pragma once

#include "../serializer/LbdsrJsonObject.h"

#include "../Backend.h"
#include "../Frontend.h"
#include "../Ports.h"

using namespace io::swagger::server::model;

class LbdsrInterface {
public:

  virtual void update(const LbdsrJsonObject &conf) = 0;
  virtual LbdsrJsonObject toJsonObject() = 0;

  /// <summary>
  /// Name of the lbdsr service
  /// </summary>
  virtual std::string getName() = 0;

  /// <summary>
  /// UUID of the Cube
  /// </summary>
  virtual std::string getUuid() = 0;

  /// <summary>
  /// Type of the Cube (TC, XDP_SKB, XDP_DRV)
  /// </summary>
  virtual CubeType getType() = 0;

  /// <summary>
  /// Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE)
  /// </summary>
  virtual LbdsrLoglevelEnum getLoglevel() = 0;
  virtual void setLoglevel(const LbdsrLoglevelEnum &value) = 0;

  /// <summary>
  /// Entry of the ports table
  /// </summary>
  virtual std::shared_ptr<Ports> getPorts(const std::string &name) = 0;
  virtual std::vector<std::shared_ptr<Ports>> getPortsList() = 0;
  virtual void addPorts(const std::string &name, const PortsJsonObject &conf) = 0;
  virtual void addPortsList(const std::vector<PortsJsonObject> &conf) = 0;
  virtual void replacePorts(const std::string &name, const PortsJsonObject &conf) = 0;
  virtual void delPorts(const std::string &name) = 0;
  virtual void delPortsList() = 0;

  /// <summary>
  /// Defines the algorithm which LB use to direct requests to the node of the pool (Random, RoundRobin, ..)
  /// </summary>
  virtual std::string getAlgorithm() = 0;
  virtual void setAlgorithm(const std::string &value) = 0;

  /// <summary>
  ///
  /// </summary>
  virtual std::shared_ptr<Frontend> getFrontend() = 0;
  virtual void addFrontend(const FrontendJsonObject &value) = 0;
  virtual void replaceFrontend(const FrontendJsonObject &conf) = 0;
  virtual void delFrontend() = 0;

  /// <summary>
  ///
  /// </summary>
  virtual std::shared_ptr<Backend> getBackend() = 0;
  virtual void addBackend(const BackendJsonObject &value) = 0;
  virtual void replaceBackend(const BackendJsonObject &conf) = 0;
  virtual void delBackend() = 0;
};

