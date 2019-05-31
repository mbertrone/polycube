/**
* monitor API generated from monitor.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/*
 * This function is called each time a packet arrives to the cube.
 * ctx contains the packet and md some additional metadata for the packet.
 * If the service is of type XDP_SKB/DRV CTX TYPE is equivalent to the struct
 * xdp_md otherwise, if the service is of type TC, CTXTYPE is equivalent to
 * the __sk_buff struct
 * Please look at the libpolycube documentation for more details.
 */
static __always_inline
int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  // Put your eBPF datapath code here
  pcn_log(ctx, LOG_INFO, "Hello from polycube! :-)");
  return RX_DROP;
}
