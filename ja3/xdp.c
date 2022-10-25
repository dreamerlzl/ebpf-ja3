// +build ignore

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

#define MAX_CPUS 128

struct event
{
  __u16 dummy;
  __u16 pkt_len;
} __packed;
struct event *unused __attribute__((unused));

struct
{
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, MAX_CPUS);
  __type(key, int);
  __type(value, __u32);
} events SEC(".maps");

int is_tls_client_hello(const unsigned char *segment,
                        const unsigned char *segment_end);

SEC("xdp")
int xdp_func(struct xdp_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *iph = data + sizeof(*eth);
  struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*iph);

  if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcp) > data_end)
  {
    return XDP_PASS;
  }

  if (eth->h_proto != htons(ETH_P_IP))
  {
    return XDP_PASS;
  }

  if (iph->protocol != IPPROTO_TCP)
  {
    // bpf_printk("not a tcp packet: %cu", iph->protocol);
    return XDP_PASS;
  }

  struct event tcp_meta;
  tcp_meta.pkt_len = (__u16)(data_end - data);

  // check this
  // https://github.com/xdp-project/xdp-tutorial/blob/d41903137d5746082b361715067f77f4f88a5d69/common/parsing_helpers.h#L247
  unsigned char *payload = (unsigned char *)tcp + (tcp->doff * 4);
  if (!is_tls_client_hello(payload, data_end))
  {
    // bpf_printk("not a tls client hello: %u\n", (__u16)(data_end - (void *)payload));
    return XDP_PASS;
  }

  tcp_meta.dummy = 1;
  __u64 flags = BPF_F_CURRENT_CPU;
  flags |= (__u64)tcp_meta.pkt_len << 32;
  int ret =
      bpf_perf_event_output(ctx, &events, flags, &tcp_meta, sizeof(tcp_meta));
  if (ret)
    bpf_printk("perf_event_output failed: %d\n", ret);
  else
  {
    bpf_printk("perf_event_output success: %d\n", tcp_meta.pkt_len);
  }

  return XDP_PASS;
}

#define recordLayerHeaderLen 5
#define contentType 22
#define tlsVersionBitmask 0xFFFC
#define tls13 0x0304
#define NO 0
#define YES 1

int is_tls_client_hello(const unsigned char *segment,
                        const unsigned char *segment_end)
{
  if (segment + recordLayerHeaderLen > segment_end)
  {
    // bpf_printk("payload size too small\n");
    return NO;
  }

  if (segment[0] != contentType)
  {
    // bpf_printk("not handshake: %u %u %u %u %u\n", segment[0], segment[1], segment[2], segment[3], segment[4]);
    return NO;
  }

  u_int16_t tls_version =
      (((u_int16_t)segment[1]) << 8) | ((u_int16_t)segment[2]);

  if (((tls_version & tlsVersionBitmask) != 0x0300) && (tls_version != tls13))
  {
    // bpf_printk("unsupported tls version: %d, %d\n", tls_version,
    //            (tls_version & tlsVersionBitmask));
    return NO;
  }

  u_int16_t segment_len =
      ((u_int16_t)segment[3] << 8) | ((u_int16_t)segment[4]);

  if ((size_t)segment_len + recordLayerHeaderLen > segment_end - segment)
  {
    // printf("invalid segment len: %lu, %d\n", payload_size, segment_len);
    return NO;
  }
  return YES;
}

char __license[] SEC("license") = "Dual MIT/GPL";
