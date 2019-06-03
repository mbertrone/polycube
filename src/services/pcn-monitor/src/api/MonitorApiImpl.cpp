/**
* monitor API generated from monitor.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */


#include "MonitorApiImpl.h"

namespace polycube {
namespace service {
namespace api {

using namespace polycube::service::model;

namespace MonitorApiImpl {
namespace {
std::unordered_map<std::string, std::shared_ptr<Monitor>> cubes;
std::mutex cubes_mutex;

std::shared_ptr<Monitor> get_cube(const std::string &name) {
  std::lock_guard<std::mutex> guard(cubes_mutex);
  auto iter = cubes.find(name);
  if (iter == cubes.end()) {
    throw std::runtime_error("Cube " + name + " does not exist");
  }

  return iter->second;
}

}

void create_monitor_by_id(const std::string &name, const MonitorJsonObject &jsonObject) {
  {
    // check if name is valid before creating it
    std::lock_guard<std::mutex> guard(cubes_mutex);
    if (cubes.count(name) != 0) {
      throw std::runtime_error("There is already a cube with name " + name);
    }
  }
  auto ptr = std::make_shared<Monitor>(name, jsonObject);
  std::unordered_map<std::string, std::shared_ptr<Monitor>>::iterator iter;
  bool inserted;

  std::lock_guard<std::mutex> guard(cubes_mutex);
  std::tie(iter, inserted) = cubes.emplace(name, std::move(ptr));

  if (!inserted) {
    throw std::runtime_error("There is already a cube with name " + name);
  }
}

void replace_monitor_by_id(const std::string &name, const MonitorJsonObject &bridge){
  throw std::runtime_error("Method not supported!");
}

void delete_monitor_by_id(const std::string &name) {
  std::lock_guard<std::mutex> guard(cubes_mutex);
  if (cubes.count(name) == 0) {
    throw std::runtime_error("Cube " + name + " does not exist");
  }
  cubes.erase(name);
}

std::vector<MonitorJsonObject> read_monitor_list_by_id() {
  std::vector<MonitorJsonObject> jsonObject_vect;
  for(auto &i : cubes) {
    auto m = get_cube(i.first);
    jsonObject_vect.push_back(m->toJsonObject());
  }
  return jsonObject_vect;
}

std::vector<nlohmann::fifo_map<std::string, std::string>> read_monitor_list_by_id_get_list() {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  for (auto &x : cubes) {
    nlohmann::fifo_map<std::string, std::string> m;
    m["name"] = x.first;
    r.push_back(std::move(m));
  }
  return r;
}

/**
* @brief   Read monitor by ID
*
* Read operation of resource: monitor*
*
* @param[in] name ID of name
*
* Responses:
* MonitorJsonObject
*/
MonitorJsonObject
read_monitor_by_id(const std::string &name) {
  return get_cube(name)->toJsonObject();

}

/**
* @brief   Read stats by ID
*
* Read operation of resource: stats*
*
* @param[in] name ID of name
*
* Responses:
* StatsJsonObject
*/
StatsJsonObject
read_monitor_stats_by_id(const std::string &name) {
  auto monitor = get_cube(name);
  return monitor->getStats()->toJsonObject();

}

/**
* @brief   Read deliverratio by ID
*
* Read operation of resource: deliverratio*
*
* @param[in] name ID of name
*
* Responses:
* uint64_t
*/
uint64_t
read_monitor_stats_deliverratio_by_id(const std::string &name) {
  auto monitor = get_cube(name);
  auto stats = monitor->getStats();
  return stats->getDeliverratio();

}

/**
* @brief   Read lastupdate by ID
*
* Read operation of resource: lastupdate*
*
* @param[in] name ID of name
*
* Responses:
* uint64_t
*/
uint64_t
read_monitor_stats_lastupdate_by_id(const std::string &name) {
  auto monitor = get_cube(name);
  auto stats = monitor->getStats();
  return stats->getLastupdate();

}

/**
* @brief   Read responseratio by ID
*
* Read operation of resource: responseratio*
*
* @param[in] name ID of name
*
* Responses:
* uint64_t
*/
uint64_t
read_monitor_stats_responseratio_by_id(const std::string &name) {
  auto monitor = get_cube(name);
  auto stats = monitor->getStats();
  return stats->getResponseratio();

}

/**
* @brief   Read tcpattemptfails by ID
*
* Read operation of resource: tcpattemptfails*
*
* @param[in] name ID of name
*
* Responses:
* uint64_t
*/
uint64_t
read_monitor_stats_tcpattemptfails_by_id(const std::string &name) {
  auto monitor = get_cube(name);
  auto stats = monitor->getStats();
  return stats->getTcpattemptfails();

}

/**
* @brief   Read tcpoutrsts by ID
*
* Read operation of resource: tcpoutrsts*
*
* @param[in] name ID of name
*
* Responses:
* uint64_t
*/
uint64_t
read_monitor_stats_tcpoutrsts_by_id(const std::string &name) {
  auto monitor = get_cube(name);
  auto stats = monitor->getStats();
  return stats->getTcpoutrsts();

}

/**
* @brief   Update monitor by ID
*
* Update operation of resource: monitor*
*
* @param[in] name ID of name
* @param[in] value monitorbody object
*
* Responses:
*
*/
void
update_monitor_by_id(const std::string &name, const MonitorJsonObject &value) {
  auto monitor = get_cube(name);

  return monitor->update(value);
}

/**
* @brief   Update monitor by ID
*
* Update operation of resource: monitor*
*
* @param[in] value monitorbody object
*
* Responses:
*
*/
void
update_monitor_list_by_id(const std::vector<MonitorJsonObject> &value) {
  throw std::runtime_error("Method not supported");
}



/*
 * help related
 */


}

}
}
}
