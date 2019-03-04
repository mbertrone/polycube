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
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

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

struct eth_hdr {
    __be64 dst : 48;
    __be64 src : 48;
    __be16 proto;
} __attribute__((packed));

/*The struct defined in tcp.h lets flags be accessed only one by one,
*it is not needed here.*/
struct tcp_hdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8 res1 : 4, doff : 4;
    __u8 flags;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((packed));



static __always_inline struct packetHeaders *getPacket(struct CTXTYPE *ctx) {
  int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct packetHeaders));
  if (ret < 0)
    return NULL;

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

  /* First of all we need to reserve the metadata space on the
   * packet and this MUST happen before loading ctx->data
   * otherwise the verifier will raise an error.
   */
  struct packetHeaders *pkt = getPacket(ctx);
  if (pkt == NULL)
    return RX_DROP;

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if (pkt + 1 > data)
    return RX_DROP;

  struct eth_hdr *ethernet = data;

  if (data + sizeof(*ethernet) > data_end)
    return RX_DROP;

  if (ethernet->proto != bpf_htons(ETH_P_IP)) {
    /*Let everything that is not IP pass. */
    pcn_log(ctx, LOG_DEBUG, "Packet not IP. Let this traffic pass by default.");
    return RX_OK;
  }

  struct iphdr *ip = NULL;
  ip = data + sizeof(struct eth_hdr);
  if (data + sizeof(struct eth_hdr) + sizeof(*ip) > data_end)
    return RX_DROP;

  pkt->srcIp = ip->saddr;
  pkt->dstIp = ip->daddr;
  pkt->l4proto = ip->protocol;

  if (ip->protocol == IPPROTO_TCP) {
    struct tcp_hdr *tcp = NULL;
    tcp = data + sizeof(struct eth_hdr) + sizeof(*ip);
    if (data + sizeof(struct eth_hdr) + sizeof(*ip) + sizeof(*tcp) > data_end)
      return RX_DROP;
    pkt->srcPort = tcp->source;
    pkt->dstPort = tcp->dest;
    pkt->seqN = tcp->seq;
    pkt->ackN = tcp->ack_seq;
    pkt->flags = tcp->flags;
  } else if (ip->protocol == IPPROTO_UDP) {
    struct udphdr *udp = NULL;
    udp = data + sizeof(struct eth_hdr) + sizeof(*ip);
    if (data + sizeof(struct eth_hdr) + sizeof(*ip) + sizeof(*udp) > data_end)
      return RX_DROP;
    pkt->srcPort = udp->source;
    pkt->dstPort = udp->dest;
  }

  call_ingress_program(ctx, 1);

  return RX_DROP;
}
