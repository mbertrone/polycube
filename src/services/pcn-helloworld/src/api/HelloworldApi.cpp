/**
* helloworld API
* Helloworld Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */


#include "HelloworldApi.h"

namespace io {
namespace swagger {
namespace server {
namespace api {

using namespace io::swagger::server::model;

HelloworldApi::HelloworldApi() {
  setup_routes();
};

void HelloworldApi::control_handler(const HttpHandleRequest &request, HttpHandleResponse &response) {
  try {
    auto s = router.route(request, response);
    if (s == Rest::Router::Status::NotFound) {
      response.send(Http::Code::Not_Found);
    }
  } catch (const std::exception &e) {
    response.send(polycube::service::Http::Code::Bad_Request, e.what());
  }
}

void HelloworldApi::setup_routes() {
  using namespace polycube::service::Rest;

  Routes::Post(router, base + ":name/", Routes::bind(&HelloworldApi::create_helloworld_by_id_handler, this));
  Routes::Post(router, base + ":name/ports/:ports_name/", Routes::bind(&HelloworldApi::create_helloworld_ports_by_id_handler, this));
  Routes::Post(router, base + ":name/ports/", Routes::bind(&HelloworldApi::create_helloworld_ports_list_by_id_handler, this));
  Routes::Delete(router, base + ":name/", Routes::bind(&HelloworldApi::delete_helloworld_by_id_handler, this));
  Routes::Delete(router, base + ":name/ports/:ports_name/", Routes::bind(&HelloworldApi::delete_helloworld_ports_by_id_handler, this));
  Routes::Delete(router, base + ":name/ports/", Routes::bind(&HelloworldApi::delete_helloworld_ports_list_by_id_handler, this));
  Routes::Get(router, base + ":name/action/", Routes::bind(&HelloworldApi::read_helloworld_action_by_id_handler, this));
  Routes::Get(router, base + ":name/", Routes::bind(&HelloworldApi::read_helloworld_by_id_handler, this));
  Routes::Get(router, base + "", Routes::bind(&HelloworldApi::read_helloworld_list_by_id_handler, this));
  Routes::Get(router, base + ":name/loglevel/", Routes::bind(&HelloworldApi::read_helloworld_loglevel_by_id_handler, this));
  Routes::Get(router, base + ":name/ports/:ports_name/", Routes::bind(&HelloworldApi::read_helloworld_ports_by_id_handler, this));
  Routes::Get(router, base + ":name/ports/", Routes::bind(&HelloworldApi::read_helloworld_ports_list_by_id_handler, this));
  Routes::Get(router, base + ":name/ports/:ports_name/peer/", Routes::bind(&HelloworldApi::read_helloworld_ports_peer_by_id_handler, this));
  Routes::Get(router, base + ":name/ports/:ports_name/status/", Routes::bind(&HelloworldApi::read_helloworld_ports_status_by_id_handler, this));
  Routes::Get(router, base + ":name/ports/:ports_name/uuid/", Routes::bind(&HelloworldApi::read_helloworld_ports_uuid_by_id_handler, this));
  Routes::Get(router, base + ":name/type/", Routes::bind(&HelloworldApi::read_helloworld_type_by_id_handler, this));
  Routes::Get(router, base + ":name/uuid/", Routes::bind(&HelloworldApi::read_helloworld_uuid_by_id_handler, this));
  Routes::Put(router, base + ":name/", Routes::bind(&HelloworldApi::replace_helloworld_by_id_handler, this));
  Routes::Put(router, base + ":name/ports/:ports_name/", Routes::bind(&HelloworldApi::replace_helloworld_ports_by_id_handler, this));
  Routes::Put(router, base + ":name/ports/", Routes::bind(&HelloworldApi::replace_helloworld_ports_list_by_id_handler, this));
  Routes::Patch(router, base + ":name/action/", Routes::bind(&HelloworldApi::update_helloworld_action_by_id_handler, this));
  Routes::Patch(router, base + ":name/", Routes::bind(&HelloworldApi::update_helloworld_by_id_handler, this));
  Routes::Patch(router, base + "", Routes::bind(&HelloworldApi::update_helloworld_list_by_id_handler, this));
  Routes::Patch(router, base + ":name/loglevel/", Routes::bind(&HelloworldApi::update_helloworld_loglevel_by_id_handler, this));
  Routes::Patch(router, base + ":name/ports/:ports_name/", Routes::bind(&HelloworldApi::update_helloworld_ports_by_id_handler, this));
  Routes::Patch(router, base + ":name/ports/", Routes::bind(&HelloworldApi::update_helloworld_ports_list_by_id_handler, this));
  Routes::Patch(router, base + ":name/ports/:ports_name/peer/", Routes::bind(&HelloworldApi::update_helloworld_ports_peer_by_id_handler, this));

  Routes::Options(router, base + ":name/", Routes::bind(&HelloworldApi::read_helloworld_by_id_help, this));
  Routes::Options(router, base + "", Routes::bind(&HelloworldApi::read_helloworld_list_by_id_help, this));
  Routes::Options(router, base + ":name/ports/:ports_name/", Routes::bind(&HelloworldApi::read_helloworld_ports_by_id_help, this));
  Routes::Options(router, base + ":name/ports/", Routes::bind(&HelloworldApi::read_helloworld_ports_list_by_id_help, this));

}

void HelloworldApi::create_helloworld_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {
    // Getting the body param
    HelloworldJsonObject value;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value.fromJson(request_body);
    value.setName(name);
    value.validateMandatoryFields();
    value.validateParams();
    create_helloworld_by_id(name, value);
    response.send(polycube::service::Http::Code::Created);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::create_helloworld_ports_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();
  auto portsName = request.param(":ports_name").as<std::string>();


  try {
    // Getting the body param
    PortsJsonObject value;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value.fromJson(request_body);
    value.setName(portsName);
    value.validateMandatoryFields();
    value.validateParams();
    create_helloworld_ports_by_id(name, portsName, value);
    response.send(polycube::service::Http::Code::Created);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::create_helloworld_ports_list_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();

  // Getting the body param
  std::vector<PortsJsonObject> value;

  try {

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    for (auto &j : request_body) {
      PortsJsonObject a;
      a.fromJson(j);
      a.validateKeys();
      a.validateMandatoryFields();
      a.validateParams();
      value.push_back(a);
    }
    create_helloworld_ports_list_by_id(name, value);
    response.send(polycube::service::Http::Code::Created);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::delete_helloworld_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {

    delete_helloworld_by_id(name);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::delete_helloworld_ports_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();
  auto portsName = request.param(":ports_name").as<std::string>();


  try {

    delete_helloworld_ports_by_id(name, portsName);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::delete_helloworld_ports_list_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {

    delete_helloworld_ports_list_by_id(name);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::read_helloworld_action_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {


    auto x = read_helloworld_action_by_id(name);
    nlohmann::json response_body;
    response_body = HelloworldJsonObject::HelloworldActionEnum_to_string(x);
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::read_helloworld_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {


    auto x = read_helloworld_by_id(name);
    nlohmann::json response_body;
    response_body = x.toJson();
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::read_helloworld_list_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {


  try {


    auto x = read_helloworld_list_by_id();
    nlohmann::json response_body;
    for (auto &i : x) {
      response_body += i.toJson();
    }
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::read_helloworld_loglevel_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {


    auto x = read_helloworld_loglevel_by_id(name);
    nlohmann::json response_body;
    response_body = HelloworldJsonObject::HelloworldLoglevelEnum_to_string(x);
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::read_helloworld_ports_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();
  auto portsName = request.param(":ports_name").as<std::string>();


  try {


    auto x = read_helloworld_ports_by_id(name, portsName);
    nlohmann::json response_body;
    response_body = x.toJson();
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::read_helloworld_ports_list_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {


    auto x = read_helloworld_ports_list_by_id(name);
    nlohmann::json response_body;
    for (auto &i : x) {
      response_body += i.toJson();
    }
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::read_helloworld_ports_peer_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();
  auto portsName = request.param(":ports_name").as<std::string>();


  try {


    auto x = read_helloworld_ports_peer_by_id(name, portsName);
    nlohmann::json response_body;
    response_body = x;
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::read_helloworld_ports_status_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();
  auto portsName = request.param(":ports_name").as<std::string>();


  try {


    auto x = read_helloworld_ports_status_by_id(name, portsName);
    nlohmann::json response_body;
    response_body = PortsJsonObject::PortsStatusEnum_to_string(x);
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::read_helloworld_ports_uuid_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();
  auto portsName = request.param(":ports_name").as<std::string>();


  try {


    auto x = read_helloworld_ports_uuid_by_id(name, portsName);
    nlohmann::json response_body;
    response_body = x;
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::read_helloworld_type_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {


    auto x = read_helloworld_type_by_id(name);
    nlohmann::json response_body;
    response_body = HelloworldJsonObject::CubeType_to_string(x);
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::read_helloworld_uuid_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {


    auto x = read_helloworld_uuid_by_id(name);
    nlohmann::json response_body;
    response_body = x;
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::replace_helloworld_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {
    // Getting the body param
    HelloworldJsonObject value;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value.fromJson(request_body);
    value.setName(name);
    value.validateMandatoryFields();
    value.validateParams();
    replace_helloworld_by_id(name, value);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::replace_helloworld_ports_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();
  auto portsName = request.param(":ports_name").as<std::string>();


  try {
    // Getting the body param
    PortsJsonObject value;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value.fromJson(request_body);
    value.setName(portsName);
    value.validateMandatoryFields();
    value.validateParams();
    replace_helloworld_ports_by_id(name, portsName, value);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::replace_helloworld_ports_list_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();

  // Getting the body param
  std::vector<PortsJsonObject> value;

  try {

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    for (auto &j : request_body) {
      PortsJsonObject a;
      a.fromJson(j);
      a.validateKeys();
      a.validateMandatoryFields();
      a.validateParams();
      value.push_back(a);
    }
    replace_helloworld_ports_list_by_id(name, value);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::update_helloworld_action_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {
    // Getting the body param
    HelloworldActionEnum value_;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value_ = HelloworldJsonObject::string_to_HelloworldActionEnum(request_body);
    update_helloworld_action_by_id(name, value_);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::update_helloworld_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {
    // Getting the body param
    HelloworldJsonObject value;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value.fromJson(request_body);
    value.setName(name);
    value.validateParams();
    update_helloworld_by_id(name, value);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::update_helloworld_list_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {

  // Getting the body param
  std::vector<HelloworldJsonObject> value;

  try {

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    for (auto &j : request_body) {
      HelloworldJsonObject a;
      a.fromJson(j);
      a.validateKeys();
      a.validateParams();
      value.push_back(a);
    }
    update_helloworld_list_by_id(value);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::update_helloworld_loglevel_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {
    // Getting the body param
    HelloworldLoglevelEnum value_;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value_ = HelloworldJsonObject::string_to_HelloworldLoglevelEnum(request_body);
    update_helloworld_loglevel_by_id(name, value_);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::update_helloworld_ports_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();
  auto portsName = request.param(":ports_name").as<std::string>();


  try {
    // Getting the body param
    PortsJsonObject value;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value.fromJson(request_body);
    value.setName(portsName);
    value.validateParams();
    update_helloworld_ports_by_id(name, portsName, value);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::update_helloworld_ports_list_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();

  // Getting the body param
  std::vector<PortsJsonObject> value;

  try {

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    for (auto &j : request_body) {
      PortsJsonObject a;
      a.fromJson(j);
      a.validateKeys();
      a.validateParams();
      value.push_back(a);
    }
    update_helloworld_ports_list_by_id(name, value);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void HelloworldApi::update_helloworld_ports_peer_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();
  auto portsName = request.param(":ports_name").as<std::string>();


  try {
    // Getting the body param
    std::string value;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    // The conversion is done automatically by the json library
    value = request_body;
    update_helloworld_ports_peer_by_id(name, portsName, value);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}

void HelloworldApi::read_helloworld_by_id_help(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  using polycube::service::HelpType;
  nlohmann::json val = nlohmann::json::object();
  switch (request.help_type()) {
  case HelpType::SHOW:
    val["params"] = HelloworldJsonObject::helpElements();
  break;

  case HelpType::ADD:
    response.send(polycube::service::Http::Code::Bad_Request);
  return;

  case HelpType::SET:
    val["params"] = HelloworldJsonObject::helpWritableLeafs();
  break;

  case HelpType::DEL:
    response.send(polycube::service::Http::Code::Bad_Request);
  return;

  case HelpType::NONE:
    val["commands"] = {"set", "show"};
    val["params"] = HelloworldJsonObject::helpComplexElements();
    val["actions"] = HelloworldJsonObject::helpActions();
  break;

  case HelpType::NO_HELP:
    response.send(polycube::service::Http::Code::Bad_Request);
    return;
  }
  response.send(polycube::service::Http::Code::Ok, val.dump(4));
}

void HelloworldApi::read_helloworld_list_by_id_help(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {


  using polycube::service::HelpType;
  nlohmann::json val = nlohmann::json::object();
  switch (request.help_type()) {
  case HelpType::SHOW:
    val["params"] = HelloworldJsonObject::helpKeys();
    val["elements"] = read_helloworld_list_by_id_get_list();
  break;

  case HelpType::ADD:
    val["params"] = HelloworldJsonObject::helpKeys();
    val["optional-params"] = HelloworldJsonObject::helpWritableLeafs();
  break;

  case HelpType::SET:
    response.send(polycube::service::Http::Code::Bad_Request);
  return;

  case HelpType::DEL:
    val["params"] = HelloworldJsonObject::helpKeys();
    val["elements"] = read_helloworld_list_by_id_get_list();
  break;

  case HelpType::NONE:
    val["commands"] = {"add", "del", "show"};
    val["params"] = HelloworldJsonObject::helpKeys();
    val["elements"] = read_helloworld_list_by_id_get_list();
  break;

  case HelpType::NO_HELP:
    response.send(polycube::service::Http::Code::Bad_Request);
    return;
  }
  response.send(polycube::service::Http::Code::Ok, val.dump(4));
}

void HelloworldApi::read_helloworld_ports_by_id_help(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();
  auto portsName = request.param(":ports_name").as<std::string>();


  using polycube::service::HelpType;
  nlohmann::json val = nlohmann::json::object();
  switch (request.help_type()) {
  case HelpType::SHOW:
    val["params"] = PortsJsonObject::helpElements();
  break;

  case HelpType::ADD:
    response.send(polycube::service::Http::Code::Bad_Request);
  return;

  case HelpType::SET:
    val["params"] = PortsJsonObject::helpWritableLeafs();
  break;

  case HelpType::DEL:
    response.send(polycube::service::Http::Code::Bad_Request);
  return;

  case HelpType::NONE:
    val["commands"] = {"set", "show"};
    val["params"] = PortsJsonObject::helpComplexElements();
    val["actions"] = PortsJsonObject::helpActions();
  break;

  case HelpType::NO_HELP:
    response.send(polycube::service::Http::Code::Bad_Request);
    return;
  }
  response.send(polycube::service::Http::Code::Ok, val.dump(4));
}

void HelloworldApi::read_helloworld_ports_list_by_id_help(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  using polycube::service::HelpType;
  nlohmann::json val = nlohmann::json::object();
  switch (request.help_type()) {
  case HelpType::SHOW:
    val["params"] = PortsJsonObject::helpKeys();
    val["elements"] = read_helloworld_ports_list_by_id_get_list(name);
  break;

  case HelpType::ADD:
    val["params"] = PortsJsonObject::helpKeys();
    val["optional-params"] = PortsJsonObject::helpWritableLeafs();
  break;

  case HelpType::SET:
    response.send(polycube::service::Http::Code::Bad_Request);
  return;

  case HelpType::DEL:
    val["params"] = PortsJsonObject::helpKeys();
    val["elements"] = read_helloworld_ports_list_by_id_get_list(name);
  break;

  case HelpType::NONE:
    val["commands"] = {"add", "del", "show"};
    val["params"] = PortsJsonObject::helpKeys();
    val["elements"] = read_helloworld_ports_list_by_id_get_list(name);
  break;

  case HelpType::NO_HELP:
    response.send(polycube::service::Http::Code::Bad_Request);
    return;
  }
  response.send(polycube::service::Http::Code::Ok, val.dump(4));
}



}
}
}
}

