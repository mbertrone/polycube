/**
* firewall API
* Firewall Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

#include "api/FirewallApiImpl.h"
#define MANAGER_TYPE io::swagger::server::api::FirewallApiImpl
#define SERVICE_DESCRIPTION "Firewall Service"
#define SERVICE_VERSION "2.0"
#define SERVICE_PYANG_GIT ""
#define SERVICE_SWAGGER_CODEGEN_GIT "c757d44b71d48df9e381fc8d35ea69bd12268127/c757d44"
#define SERVICE_REQUIRED_KERNEL_VERSION "4.14.0"

const std::string SERVICE_DATA_MODEL = R"POLYCUBE_DM(
module firewall {
  yang-version 1.1;
  namespace "http://polycube.network/firewall";
  prefix "firewall";

  import polycube-base { prefix "basemodel"; }

  organization "Polycube open source project";
  description "YANG data model for the Polycube Firewall service";

  basemodel:service-description "Firewall Service";
  basemodel:service-version "2.0";
  basemodel:service-name "firewall";
  basemodel:service-min-kernel-version "4.14.0";

  uses "basemodel:base-yang-module";

  typedef action {
    type enumeration {
      enum DROP;
      enum LOG;
      enum FORWARD;
    }
    default DROP;
  }

  typedef conntrackstatus {
    type enumeration {
      enum NEW;
      enum ESTABLISHED;
      enum RELATED;
      enum INVALID;
    }
  }


  grouping rule-fields {
    leaf src {
      type string;
      description "Source IP Address.";
      basemodel:init-only-config;
      basemodel:cli-example "10.0.0.1/24";
    }

    leaf dst {
      type string;
      description "Destination IP Address.";
      basemodel:init-only-config;
      basemodel:cli-example "10.0.0.2/24";
    }

    leaf l4proto {
      type string;
      basemodel:init-only-config;
      description "Level 4 Protocol.";
    }

    leaf sport {
      type uint16;
      basemodel:init-only-config;
      description "Source L4 Port";
    }

    leaf dport {
      type uint16;
      basemodel:init-only-config;
      description "Destination L4 Port";
    }

    leaf tcpflags {
      type string;
      basemodel:init-only-config;
      description "TCP flags. Allowed values: SYN, FIN, ACK, RST, PSH, URG, CWR, ECE. ! means set to 0.";
      basemodel:cli-example "!FIN,SYN,!RST,!ACK";
    }

    leaf conntrack {
      type conntrackstatus;
      basemodel:init-only-config;
      description "Connection status (NEW, ESTABLISHED, RELATED, INVALID)";
    }


    leaf action {
      type action;
      basemodel:init-only-config;
      description "Action if the rule matches. Default is DROP.";
      basemodel:cli-example "DROP, FORWARD, LOG";
    }

    leaf description {
      type string;
      basemodel:init-only-config;
      description "Description of the rule.";
      basemodel:cli-example "This rule blocks incoming SSH connections.";
    }
  }

  leaf ingress-port {
    type string;
    description "Name for the ingress port, from which arrives traffic processed by INGRESS chain (by default it's the first port of the cube)";
  }

  leaf egress-port {
    type string;
    description "Name for the egress port, from which arrives traffic processed by EGRESS chain (by default it's the second port of the cube)";
  }

  leaf conntrack {
    type enumeration {
      enum ON;
      enum OFF;
    }
    description "Enables the Connection Tracking module. Mandatory if connection tracking rules are needed. Default is ON.";
  }

  leaf accept-established {
    type enumeration {
      enum ON;
      enum OFF;
    }
    description "If Connection Tracking is enabled, all packets belonging to ESTABLISHED connections will be forwarded automatically. Default is ON.";
  }

  leaf interactive {
    type boolean;
    description "Interactive mode applies new rules immediately; if 'false', the command 'apply-rules' has to be used to apply all the rules at once. Default is TRUE.";
        default true;
  }

  list session-table {
    key "src dst l4proto sport dport";
    config false;
    leaf src {
      type string;
      config false;
      description "Source IP";
    }

    leaf dst {
      type string;
      config false;
      description "Destination IP";
    }

    leaf l4proto {
      type string;
      config false;
      description "Level 4 Protocol.";
    }


    leaf sport {
      type uint16;
      description "Source Port";
      config false;
    }

    leaf dport {
      type uint16;
      description "Destination";
      config false;
    }

    leaf state {
      type string;
      config false;
      description "Connection state.";
    }

    leaf eta {
      type uint32;
      config false;
      description "Last packet matching the connection";
    }
  }

  list chain {
    key "name";

    leaf name {
      type enumeration {
        enum INGRESS;
        enum EGRESS;
        enum INVALID;
      }
      description "Chain in which the rule will be inserted. Default: INGRESS.";
      basemodel:cli-example "INGRESS, EGRESS.";
    }

    leaf default {
      type action;
      description "Default action if no rule matches in the ingress chain. Default is DROP.";
      basemodel:cli-example "DROP, FORWARD, LOG";
    }

    list stats {
      key "id";
      config false;
      leaf id {
        type uint32;
        config false;
        description "Rule Identifier";
      }

      leaf pkts {
        type uint64;
        description "Number of packets matching the rule";
        config false;
      }

      leaf bytes {
        type uint64;
        description "Number of bytes matching the rule";
        config false;
      }

      uses "firewall:rule-fields";
    }

    list rule {
      key "id";
      leaf id {
        type uint32;
        description "Rule Identifier";
      }

      uses "firewall:rule-fields";
    }

    action append {
      input {
        uses "firewall:rule-fields";
      }
      output {
        leaf id {
          type uint32;
        }
      }
    }

    action reset-counters {
      description "Reset the counters to 0 for the chain.";
      output {
        leaf result {
          type boolean;
          description "True if the operation is successful";
        }
      }
    }

    action apply-rules {
      description "Applies the rules when in batch mode (interactive==false)";
      output {
        leaf result {
          type boolean;
          description "True if the operation is successful";
        }
      }
    }
  }
}

)POLYCUBE_DM";

extern "C" const char *data_model() {
  return SERVICE_DATA_MODEL.c_str();
}


#include <polycube/services/shared_library.h>
