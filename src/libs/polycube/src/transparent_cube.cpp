/*
 * Copyright 2018 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "polycube/services/transparent_cube.h"

#include <tins/ethernetII.h>

namespace polycube {
namespace service {

TransparentCube::TransparentCube(const std::string &name,
                                 const std::vector<std::string> &ingress_code,
                                 const std::vector<std::string> &egress_code,
                                 const CubeType type, LogLevel level)
    : BaseCube(name, ingress_code, egress_code, type, level) {
  handle_packet_in = [&](const PacketIn *md,
                         const std::vector<uint8_t> &packet) -> void {
    // This lock guarantees:
    // - service implementation is not deleted wile processing it
    std::lock_guard<std::mutex> guard(cube_mutex);
    if (dismounted_)
      return;

    Sense sense = static_cast<Sense>(md->port_id);
    PacketInMetadata md_;
    md_.reason = md->reason;
    md_.metadata[0] = md->metadata[0];
    md_.metadata[1] = md->metadata[1];
    md_.metadata[2] = md->metadata[2];
    packet_in(sense, md_, packet);
  };

  cube_ = factory_->create_transparent_cube(
      name, ingress_code, egress_code, handle_log_msg, type, handle_packet_in,
      std::bind(&TransparentCube::attach, this), level);
  // TODO: where to keep this reference?, keep a double reference?
  BaseCube::cube_ = cube_;
}

TransparentCube::~TransparentCube() {
  // just in case
  dismount();

  // handle_packet_in = nullptr;

  factory_->destroy_cube(get_name());
}

std::string TransparentCube::get_parent_parameter(
    const std::string &parameter) {
  return cube_->get_parent_parameter(parameter);
}

void TransparentCube::send_packet_out(EthernetII &packet, Sense sense,
                                      bool recirculate) {
  cube_->send_packet_out(packet.serialize(), sense, recirculate);
}

void TransparentCube::attach() {}

}  // namespace service
}  // namespace polycube