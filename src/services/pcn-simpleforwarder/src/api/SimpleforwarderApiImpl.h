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

/*
* SimpleforwarderApiImpl.h
*
*
*/

#pragma once

#include "SimpleforwarderApi.h"


#include <memory>
#include <map>
#include <mutex>
#include "../Simpleforwarder.h"

#include "ActionsJsonObject.h"
#include "PortsJsonObject.h"
#include "SimpleforwarderJsonObject.h"
#include <vector>

namespace io {
namespace swagger {
namespace server {
namespace api {

using namespace io::swagger::server::model;

class SimpleforwarderApiImpl : public io::swagger::server::api::SimpleforwarderApi {
public:
  SimpleforwarderApiImpl();
  ~SimpleforwarderApiImpl() { };

  void create_simpleforwarder_actions_by_id(const std::string &name, const std::string &inport, const ActionsJsonObject &value);
  void create_simpleforwarder_actions_list_by_id(const std::string &name, const std::vector<ActionsJsonObject> &value);
  void create_simpleforwarder_by_id(const std::string &name, const SimpleforwarderJsonObject &value);
  void create_simpleforwarder_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &value);
  void create_simpleforwarder_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &value);
  void delete_simpleforwarder_actions_by_id(const std::string &name, const std::string &inport);
  void delete_simpleforwarder_actions_list_by_id(const std::string &name);
  void delete_simpleforwarder_by_id(const std::string &name);
  void delete_simpleforwarder_ports_by_id(const std::string &name, const std::string &portsName);
  void delete_simpleforwarder_ports_list_by_id(const std::string &name);
  ActionsActionEnum read_simpleforwarder_actions_action_by_id(const std::string &name, const std::string &inport);
  ActionsJsonObject read_simpleforwarder_actions_by_id(const std::string &name, const std::string &inport);
  std::vector<ActionsJsonObject> read_simpleforwarder_actions_list_by_id(const std::string &name);
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_simpleforwarder_actions_list_by_id_get_list(const std::string &name);
  std::string read_simpleforwarder_actions_outport_by_id(const std::string &name, const std::string &inport);
  SimpleforwarderJsonObject read_simpleforwarder_by_id(const std::string &name);
  std::vector<SimpleforwarderJsonObject> read_simpleforwarder_list_by_id();
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_simpleforwarder_list_by_id_get_list();
  SimpleforwarderLoglevelEnum read_simpleforwarder_loglevel_by_id(const std::string &name);
  PortsJsonObject read_simpleforwarder_ports_by_id(const std::string &name, const std::string &portsName);
  std::vector<PortsJsonObject> read_simpleforwarder_ports_list_by_id(const std::string &name);
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_simpleforwarder_ports_list_by_id_get_list(const std::string &name);
  std::string read_simpleforwarder_ports_peer_by_id(const std::string &name, const std::string &portsName);
  PortsStatusEnum read_simpleforwarder_ports_status_by_id(const std::string &name, const std::string &portsName);
  std::string read_simpleforwarder_ports_uuid_by_id(const std::string &name, const std::string &portsName);
  CubeType read_simpleforwarder_type_by_id(const std::string &name);
  std::string read_simpleforwarder_uuid_by_id(const std::string &name);
  void replace_simpleforwarder_actions_by_id(const std::string &name, const std::string &inport, const ActionsJsonObject &value);
  void replace_simpleforwarder_actions_list_by_id(const std::string &name, const std::vector<ActionsJsonObject> &value);
  void replace_simpleforwarder_by_id(const std::string &name, const SimpleforwarderJsonObject &value);
  void replace_simpleforwarder_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &value);
  void replace_simpleforwarder_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &value);
  void update_simpleforwarder_actions_action_by_id(const std::string &name, const std::string &inport, const ActionsActionEnum &value);
  void update_simpleforwarder_actions_by_id(const std::string &name, const std::string &inport, const ActionsJsonObject &value);
  void update_simpleforwarder_actions_list_by_id(const std::string &name, const std::vector<ActionsJsonObject> &value);
  void update_simpleforwarder_actions_outport_by_id(const std::string &name, const std::string &inport, const std::string &value);
  void update_simpleforwarder_by_id(const std::string &name, const SimpleforwarderJsonObject &value);
  void update_simpleforwarder_list_by_id(const std::vector<SimpleforwarderJsonObject> &value);
  void update_simpleforwarder_loglevel_by_id(const std::string &name, const SimpleforwarderLoglevelEnum &value);
  void update_simpleforwarder_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &value);
  void update_simpleforwarder_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &value);
  void update_simpleforwarder_ports_peer_by_id(const std::string &name, const std::string &portsName, const std::string &value);

private:
  std::unordered_map<std::string, std::shared_ptr<Simpleforwarder>> cubes;
  std::shared_ptr<Simpleforwarder> get_cube(const std::string &name);
  std::mutex cubes_mutex;
};

}
}
}
}

