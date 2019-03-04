/*
 * Copyright 2017 The Polycube Authors
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

/*
 * This file contains the eBPF code that implements the service datapath.
 * Of course it is no required to have this into a separated file, however
 * it could be a good idea in order to better organize the code.
 */

#include <bcc/helpers.h>
#include <bcc/proto.h>

struct packetHeaders {
    uint32_t srcIp;
    uint32_t dstIp;
    uint8_t l4proto;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t flags;
    uint32_t seqN;
    uint32_t ackN;
    uint8_t connStatus;
}; // todo packed

static __always_inline struct packetHeaders *getPacket(struct CTXTYPE *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *meta = (void *)(unsigned long)ctx->data_meta;

  return meta;
}

/*
 * This function is called each time a packet arrives to the cube.
 * ctx contains the packet and md some additional metadata for the packet.
 * If the service is of type XDP_SKB/DRV CTXTYPE is equivalent to the struct
 * xdp_md
 * otherwise, if the service is of type TC, CTXTYPE is equivalent to the
 * __sk_buff struct
 * Please look at the polycube documentation for more details.
 */
static int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  pcn_log(ctx, LOG_DEBUG, "Receiving packet from port %d", md->in_port);

  struct packetHeaders *pkt = getPacket(ctx);
  if (pkt == NULL)
    return RX_DROP;

//  pcn_log(ctx, LOG_DEBUG, "Reading metadata %x ", pkt->srcIp);

  call_ingress_program(ctx, 2);
  return RX_DROP;
}
