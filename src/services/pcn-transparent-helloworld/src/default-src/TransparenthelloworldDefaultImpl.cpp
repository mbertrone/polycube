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


// These methods have a default implementation. Your are free to keep it or add your own


#include "../Transparenthelloworld.h"




std::string Transparenthelloworld::getName(){
  // This method retrieves the name value.
  return get_name();
}


std::string Transparenthelloworld::getUuid(){
  // This method retrieves the uuid value.
  return get_uuid().str();
}


CubeType Transparenthelloworld::getType(){
  // This method retrieves the type value.
  return get_type();
}


TransparenthelloworldLoglevelEnum Transparenthelloworld::getLoglevel(){
  // This method retrieves the loglevel value.
    switch(get_log_level()){
      case polycube::LogLevel::TRACE:
        return TransparenthelloworldLoglevelEnum::TRACE;
      case polycube::LogLevel::DEBUG:
        return TransparenthelloworldLoglevelEnum::DEBUG;
      case polycube::LogLevel::INFO:
        return TransparenthelloworldLoglevelEnum::INFO;
      case polycube::LogLevel::WARN:
        return TransparenthelloworldLoglevelEnum::WARN;
      case polycube::LogLevel::ERR:
        return TransparenthelloworldLoglevelEnum::ERR;
      case polycube::LogLevel::CRITICAL:
        return TransparenthelloworldLoglevelEnum::CRITICAL;
      case polycube::LogLevel::OFF:
        return TransparenthelloworldLoglevelEnum::OFF;
    }
}

void Transparenthelloworld::setLoglevel(const TransparenthelloworldLoglevelEnum &value){
  // This method sets the loglevel value.
    switch(value){
      case TransparenthelloworldLoglevelEnum::TRACE:
        set_log_level(polycube::LogLevel::TRACE);
        break;
      case TransparenthelloworldLoglevelEnum::DEBUG:
        set_log_level(polycube::LogLevel::DEBUG);
        break;
      case TransparenthelloworldLoglevelEnum::INFO:
        set_log_level(polycube::LogLevel::INFO);
        break;
      case TransparenthelloworldLoglevelEnum::WARN:
        set_log_level(polycube::LogLevel::WARN);
        break;
      case TransparenthelloworldLoglevelEnum::ERR:
        set_log_level(polycube::LogLevel::ERR);
        break;
      case TransparenthelloworldLoglevelEnum::CRITICAL:
        set_log_level(polycube::LogLevel::CRITICAL);
        break;
      case TransparenthelloworldLoglevelEnum::OFF:
        set_log_level(polycube::LogLevel::OFF);
        break;
    }
}





