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

/* ===================================
   Match on Connection Tracking Status.
   =================================== */

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define CONNTRACK_INVALID 0

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
};

BPF_TABLE("extern", int, struct packetHeaders, packet, 1);
static __always_inline struct packetHeaders *getPacket() {
  int key = 0;
  return packet.lookup(&key);
}

#if _NR_ELEMENTS > 0
struct elements {
  uint64_t bits[_MAXRULES];
};

BPF_TABLE("extern", int, struct elements, sharedEle, 1);
static __always_inline struct elements *getShared() {
  int key = 0;
  return sharedEle.lookup(&key);
}

BPF_ARRAY(Conntrack_DIRECTION, struct elements, 4);
static __always_inline struct elements *getBitVect(uint32_t *key) {
  return Conntrack_DIRECTION.lookup(key);
}
#endif

static int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  pcn_log(ctx, LOG_DEBUG, "[_CHAIN_NAME][ConntrackMatch]: Receiving packet");
/*The struct elements and the lookup table are defined only if _NR_ELEMENTS>0,
 * so this code has to be used only in this case.*/
#if _NR_ELEMENTS > 0
  int key = 0;
  struct packetHeaders *pkt = getPacket();
  if (pkt == NULL) {
    // Not possible
    return RX_DROP;
  }

  uint8_t connStatus = pkt->connStatus;
  uint32_t ct = connStatus;
  pcn_log(ctx, LOG_DEBUG,
          "[_CHAIN_NAME][ConntrackMatch]: received a packet with state %d",
          pkt->connStatus);

  struct elements *ele = getBitVect(&ct);

  if (ele == NULL) {
    pcn_log(ctx, LOG_DEBUG,
            "[_CHAIN_NAME][ConntrackMatch]: Array Lookup miss. this should never happen.");
    return RX_DROP;
  }
  struct elements *result = getShared();
  if (result == NULL) {
    /*Can't happen. The PERCPU is preallocated.*/
    return RX_DROP;
  } else {
    /*#pragma unroll does not accept a loop with a single iteration, so we need
     * to
     * distinguish cases to avoid a verifier error.*/
    bool isAllZero = true;
#if _NR_ELEMENTS == 1
    (result->bits)[0] = (ele->bits)[0] & (result->bits)[0];
    if (result->bits[0] != 0)
      isAllZero = false;
#else
    int i = 0;
#pragma unroll
    for (i = 0; i < _NR_ELEMENTS; ++i) {
      (result->bits)[i] = (result->bits)[i] & (ele->bits)[i];
      if (result->bits[i] != 0)
        isAllZero = false;
    }

#endif
    if (isAllZero) {
      pcn_log(
          ctx, LOG_DEBUG,
          "[_CHAIN_NAME][ConntrackMatch]: Bitvector is all zero. Break pipeline.");
      _DEFAULTACTION
    }
  }  // if result == NULL

  call_next_program(ctx, _NEXT_HOP_1);
#else
  return RX_DROP;
#endif

  return RX_DROP;
}
