/**
* transparenthelloworld API
* Transparent-Helloworld Service
*
* OpenAPI spec version: 1.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */


#include "TransparenthelloworldApi.h"

namespace io {
namespace swagger {
namespace server {
namespace api {

using namespace io::swagger::server::model;

TransparenthelloworldApi::TransparenthelloworldApi() {
  setup_routes();
};

void TransparenthelloworldApi::control_handler(const HttpHandleRequest &request, HttpHandleResponse &response) {
  try {
    auto s = router.route(request, response);
    if (s == Rest::Router::Status::NotFound) {
      response.send(Http::Code::Not_Found);
    }
  } catch (const std::exception &e) {
    response.send(polycube::service::Http::Code::Bad_Request, e.what());
  }
}

void TransparenthelloworldApi::setup_routes() {
  using namespace polycube::service::Rest;

  Routes::Post(router, base + ":name/", Routes::bind(&TransparenthelloworldApi::create_transparenthelloworld_by_id_handler, this));
  Routes::Delete(router, base + ":name/", Routes::bind(&TransparenthelloworldApi::delete_transparenthelloworld_by_id_handler, this));
  Routes::Get(router, base + ":name/", Routes::bind(&TransparenthelloworldApi::read_transparenthelloworld_by_id_handler, this));
  Routes::Get(router, base + ":name/egress-action/", Routes::bind(&TransparenthelloworldApi::read_transparenthelloworld_egress_action_by_id_handler, this));
  Routes::Get(router, base + ":name/ingress-action/", Routes::bind(&TransparenthelloworldApi::read_transparenthelloworld_ingress_action_by_id_handler, this));
  Routes::Get(router, base + "", Routes::bind(&TransparenthelloworldApi::read_transparenthelloworld_list_by_id_handler, this));
  Routes::Get(router, base + ":name/loglevel/", Routes::bind(&TransparenthelloworldApi::read_transparenthelloworld_loglevel_by_id_handler, this));
  Routes::Get(router, base + ":name/type/", Routes::bind(&TransparenthelloworldApi::read_transparenthelloworld_type_by_id_handler, this));
  Routes::Get(router, base + ":name/uuid/", Routes::bind(&TransparenthelloworldApi::read_transparenthelloworld_uuid_by_id_handler, this));
  Routes::Put(router, base + ":name/", Routes::bind(&TransparenthelloworldApi::replace_transparenthelloworld_by_id_handler, this));
  Routes::Patch(router, base + ":name/", Routes::bind(&TransparenthelloworldApi::update_transparenthelloworld_by_id_handler, this));
  Routes::Patch(router, base + ":name/egress-action/", Routes::bind(&TransparenthelloworldApi::update_transparenthelloworld_egress_action_by_id_handler, this));
  Routes::Patch(router, base + ":name/ingress-action/", Routes::bind(&TransparenthelloworldApi::update_transparenthelloworld_ingress_action_by_id_handler, this));
  Routes::Patch(router, base + "", Routes::bind(&TransparenthelloworldApi::update_transparenthelloworld_list_by_id_handler, this));
  Routes::Patch(router, base + ":name/loglevel/", Routes::bind(&TransparenthelloworldApi::update_transparenthelloworld_loglevel_by_id_handler, this));

  Routes::Options(router, base + ":name/", Routes::bind(&TransparenthelloworldApi::read_transparenthelloworld_by_id_help, this));
  Routes::Options(router, base + "", Routes::bind(&TransparenthelloworldApi::read_transparenthelloworld_list_by_id_help, this));

}

void TransparenthelloworldApi::create_transparenthelloworld_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {
    // Getting the body param
    TransparenthelloworldJsonObject value;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value.fromJson(request_body);
    value.setName(name);
    value.validateMandatoryFields();
    value.validateParams();
    create_transparenthelloworld_by_id(name, value);
    response.send(polycube::service::Http::Code::Created);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::delete_transparenthelloworld_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {

    delete_transparenthelloworld_by_id(name);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::read_transparenthelloworld_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {


    auto x = read_transparenthelloworld_by_id(name);
    nlohmann::json response_body;
    response_body = x.toJson();
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::read_transparenthelloworld_egress_action_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {


    auto x = read_transparenthelloworld_egress_action_by_id(name);
    nlohmann::json response_body;
    response_body = TransparenthelloworldJsonObject::TransparenthelloworldEgressActionEnum_to_string(x);
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::read_transparenthelloworld_ingress_action_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {


    auto x = read_transparenthelloworld_ingress_action_by_id(name);
    nlohmann::json response_body;
    response_body = TransparenthelloworldJsonObject::TransparenthelloworldIngressActionEnum_to_string(x);
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::read_transparenthelloworld_list_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {


  try {


    auto x = read_transparenthelloworld_list_by_id();
    nlohmann::json response_body;
    for (auto &i : x) {
      response_body += i.toJson();
    }
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::read_transparenthelloworld_loglevel_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {


    auto x = read_transparenthelloworld_loglevel_by_id(name);
    nlohmann::json response_body;
    response_body = TransparenthelloworldJsonObject::TransparenthelloworldLoglevelEnum_to_string(x);
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::read_transparenthelloworld_type_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {


    auto x = read_transparenthelloworld_type_by_id(name);
    nlohmann::json response_body;
    response_body = TransparenthelloworldJsonObject::CubeType_to_string(x);
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::read_transparenthelloworld_uuid_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {


    auto x = read_transparenthelloworld_uuid_by_id(name);
    nlohmann::json response_body;
    response_body = x;
    response.send(polycube::service::Http::Code::Ok, response_body.dump(4));

  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::replace_transparenthelloworld_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {
    // Getting the body param
    TransparenthelloworldJsonObject value;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value.fromJson(request_body);
    value.setName(name);
    value.validateMandatoryFields();
    value.validateParams();
    replace_transparenthelloworld_by_id(name, value);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::update_transparenthelloworld_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {
    // Getting the body param
    TransparenthelloworldJsonObject value;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value.fromJson(request_body);
    value.setName(name);
    value.validateParams();
    update_transparenthelloworld_by_id(name, value);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::update_transparenthelloworld_egress_action_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {
    // Getting the body param
    TransparenthelloworldEgressActionEnum value_;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value_ = TransparenthelloworldJsonObject::string_to_TransparenthelloworldEgressActionEnum(request_body);
    update_transparenthelloworld_egress_action_by_id(name, value_);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::update_transparenthelloworld_ingress_action_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {
    // Getting the body param
    TransparenthelloworldIngressActionEnum value_;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value_ = TransparenthelloworldJsonObject::string_to_TransparenthelloworldIngressActionEnum(request_body);
    update_transparenthelloworld_ingress_action_by_id(name, value_);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::update_transparenthelloworld_list_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {

  // Getting the body param
  std::vector<TransparenthelloworldJsonObject> value;

  try {

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    for (auto &j : request_body) {
      TransparenthelloworldJsonObject a;
      a.fromJson(j);
      a.validateKeys();
      a.validateParams();
      value.push_back(a);
    }
    update_transparenthelloworld_list_by_id(value);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}
void TransparenthelloworldApi::update_transparenthelloworld_loglevel_by_id_handler(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  try {
    // Getting the body param
    TransparenthelloworldLoglevelEnum value_;

    nlohmann::json request_body = nlohmann::json::parse(request.body());
    value_ = TransparenthelloworldJsonObject::string_to_TransparenthelloworldLoglevelEnum(request_body);
    update_transparenthelloworld_loglevel_by_id(name, value_);
    response.send(polycube::service::Http::Code::Ok);
  } catch(const std::exception &e) {
    response.send(polycube::service::Http::Code::Internal_Server_Error, e.what());
  }
}

void TransparenthelloworldApi::read_transparenthelloworld_by_id_help(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {
  // Getting the path params
  auto name = request.param(":name").as<std::string>();


  using polycube::service::HelpType;
  nlohmann::json val = nlohmann::json::object();
  switch (request.help_type()) {
  case HelpType::SHOW:
    val["params"] = TransparenthelloworldJsonObject::helpElements();
  break;

  case HelpType::ADD:
    response.send(polycube::service::Http::Code::Bad_Request);
  return;

  case HelpType::SET:
    val["params"] = TransparenthelloworldJsonObject::helpWritableLeafs();
  break;

  case HelpType::DEL:
    response.send(polycube::service::Http::Code::Bad_Request);
  return;

  case HelpType::NONE:
    val["commands"] = {"set", "show"};
    val["params"] = TransparenthelloworldJsonObject::helpComplexElements();
    val["actions"] = TransparenthelloworldJsonObject::helpActions();
  break;

  case HelpType::NO_HELP:
    response.send(polycube::service::Http::Code::Bad_Request);
    return;
  }
  response.send(polycube::service::Http::Code::Ok, val.dump(4));
}

void TransparenthelloworldApi::read_transparenthelloworld_list_by_id_help(
  const polycube::service::Rest::Request &request,
  polycube::service::HttpHandleResponse &response) {


  using polycube::service::HelpType;
  nlohmann::json val = nlohmann::json::object();
  switch (request.help_type()) {
  case HelpType::SHOW:
    val["params"] = TransparenthelloworldJsonObject::helpKeys();
    val["elements"] = read_transparenthelloworld_list_by_id_get_list();
  break;

  case HelpType::ADD:
    val["params"] = TransparenthelloworldJsonObject::helpKeys();
    val["optional-params"] = TransparenthelloworldJsonObject::helpWritableLeafs();
  break;

  case HelpType::SET:
    response.send(polycube::service::Http::Code::Bad_Request);
  return;

  case HelpType::DEL:
    val["params"] = TransparenthelloworldJsonObject::helpKeys();
    val["elements"] = read_transparenthelloworld_list_by_id_get_list();
  break;

  case HelpType::NONE:
    val["commands"] = {"add", "del", "show"};
    val["params"] = TransparenthelloworldJsonObject::helpKeys();
    val["elements"] = read_transparenthelloworld_list_by_id_get_list();
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

