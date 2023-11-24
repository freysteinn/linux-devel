// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp/parsing_helpers.h"

#define IPV6_FLOWINFO_MASK              cpu_to_be32(0x0FFFFFFF)

struct flow_address {
	struct in6_addr ip;
	__u16 port;
	__u16 reserved;
};

struct flow_state {
	__u32 pkts;
	__u32 root_finish_bytes;
	__u32 finish_bytes;
	__u16 root_weight;
	__u16 weight;
	__u32 persistent;
	__u64 root_priority;
};

struct network_tuple {
	struct flow_address saddr;
	struct flow_address daddr;
	__u16 proto;
	__u8 ipv;
	__u8 reserved;
};

struct pifo_map {
	__uint(type, BPF_MAP_TYPE_PIFO_XDP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1024);
	__uint(map_extra, 8192); /* range */
} pmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} xdp_tx_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 64);
	__array(values, struct pifo_map);
} pifo_maps SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct network_tuple);
	__type(value, struct flow_state);
	__uint(max_entries, 16384);
} flow_state_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 64);
	__array(values, struct flow_state_map);
} flow_state_maps SEC(".maps");



// helpers
struct parsing_context {
	void *data;            // Start of eth hdr
	void *data_end;        // End of safe acessible area
	void *meta;            // Meta data
	struct hdr_cursor nh;  // Position to parse next
	__u32 pkt_len;         // Full packet length (headers+data)
};

struct packet_info {
	struct ethhdr *eth;
	union {
		struct iphdr *iph;
		struct ipv6hdr *ip6h;
	};
	union {
		struct udphdr *udph;
		struct tcphdr *tcph;
	};
	struct network_tuple nt;
	int eth_type;
	int ip_type;
};


static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
        void *val;
        long err;

        val = bpf_map_lookup_elem(map, key);
        if (val)
                return val;

        err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
        if (err && err != -EEXIST)
                return NULL;

        return bpf_map_lookup_elem(map, key);
}

static __always_inline int bpf_max(__u64 left, __u64 right)
{
        return right > left ? right : left;
}

/*
 * Maps an IPv4 address into an IPv6 address according to RFC 4291 sec 2.5.5.2
 */
static void map_ipv4_to_ipv6(struct in6_addr *ipv6, __be32 ipv4)
{
	__builtin_memset(&ipv6->in6_u.u6_addr8[0], 0x00, 10);
	__builtin_memset(&ipv6->in6_u.u6_addr8[10], 0xff, 2);
	ipv6->in6_u.u6_addr32[3] = ipv4;
}

static __always_inline int parse_packet(struct parsing_context *pctx,
					struct bpf_fib_lookup *fib_params,
					struct packet_info *p_info)
{
	__builtin_memset(fib_params, 0, sizeof(*fib_params));

	/* Parse Ethernet and IP/IPv6 headers */
	p_info->eth_type = parse_ethhdr(&pctx->nh, pctx->data_end, &p_info->eth);
	if (p_info->eth_type < 0)
		goto err;
	if (p_info->eth_type == bpf_htons(ETH_P_IP)) {
		p_info->ip_type = parse_iphdr(&pctx->nh, pctx->data_end, &p_info->iph);

		if (p_info->ip_type < 0)
			goto err;

		if (p_info->iph->ttl <= 1)
			goto pass;

		p_info->nt.ipv = 4;
		map_ipv4_to_ipv6(&p_info->nt.saddr.ip, p_info->iph->saddr);
		map_ipv4_to_ipv6(&p_info->nt.daddr.ip, p_info->iph->daddr);

		fib_params->family	= AF_INET;
		fib_params->tos		= p_info->iph->tos;
		fib_params->l4_protocol	= p_info->iph->protocol;
		fib_params->sport	= 0;
		fib_params->dport	= 0;
		fib_params->tot_len	= ntohs(p_info->iph->tot_len);
		fib_params->ipv4_src	= p_info->iph->saddr;
		fib_params->ipv4_dst	= p_info->iph->daddr;
	} else if (p_info->eth_type == bpf_htons(ETH_P_IPV6)) {
		struct in6_addr *src = (struct in6_addr *) fib_params->ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) fib_params->ipv6_dst;
		p_info->ip_type = parse_ip6hdr(&pctx->nh, pctx->data_end, &p_info->ip6h);

		if (p_info->ip_type < 0)
			goto err;

		if (p_info->ip6h->hop_limit <= 1)
			goto pass;

		p_info->nt.ipv = 6;
 		p_info->nt.saddr.ip = p_info->ip6h->saddr;
		p_info->nt.daddr.ip = p_info->ip6h->daddr;

		fib_params->family	= AF_INET6;
		fib_params->flowinfo	= *(__be32 *)p_info->ip6h & IPV6_FLOWINFO_MASK;
		fib_params->l4_protocol	= p_info->ip6h->nexthdr;
		fib_params->sport	= 0;
		fib_params->dport	= 0;
		fib_params->tot_len	= ntohs(p_info->ip6h->payload_len);
		*src			= p_info->ip6h->saddr;
		*dst			= p_info->ip6h->daddr;
	} else {
		goto out;
	}

	/* Parse UDP and TCP headers */
	if (p_info->ip_type == IPPROTO_UDP) {
		p_info->nt.proto = IPPROTO_UDP;
		p_info->nt.saddr.port = p_info->udph->source;
		p_info->nt.daddr.port = p_info->udph->dest;
		if (parse_udphdr(&pctx->nh, pctx->data_end, &p_info->udph) < 0)
			goto err;
	}
	else if (p_info->ip_type == IPPROTO_TCP) {
		p_info->nt.proto = IPPROTO_TCP;
		p_info->nt.saddr.port = p_info->tcph->source;
		p_info->nt.saddr.port = p_info->tcph->dest;;
		if (parse_tcphdr(&pctx->nh, pctx->data_end, &p_info->tcph) < 0)
			goto err;
	}
out:
	return 0;
pass:
	return 1;
err:
	return -1;
}


/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	u32 check = (__force u32)iph->check;

	check += (__force u32)htons(0x0100);
	iph->check = (__force __sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}


// Sprio scheduler
__u32 default_weight = 256;

SEC("xdp")
int xdp_sprio_prog(struct xdp_md *ctx)
{
	struct parsing_context pctx = {
		.data = (void *)(long)ctx->data,
		.data_end = (void *)(long)ctx->data_end,
		.pkt_len = (ctx->data_end - ctx->data) & 0xffff,
		.nh = { .pos = (void *)(long)ctx->data },
	};
	struct bpf_fib_lookup fib_params;
	struct packet_info p_info = {};
	struct network_tuple nt = {0};
	struct flow_state *flow;
	struct flow_state new_flow = {0};
	__u32 prio = 0;

	int rc = parse_packet(&pctx, &fib_params, &p_info);

	if (rc < 0)
		return XDP_DROP;
	else if (rc > 0)
		return XDP_PASS;

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), false);
	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		if (!bpf_map_lookup_elem(&xdp_tx_ports, &fib_params.ifindex))
			return XDP_PASS;

		if (p_info.eth_type == htons(ETH_P_IP) && p_info.iph != NULL)
			ip_decrease_ttl(p_info.iph);
		else if (p_info.eth_type == htons(ETH_P_IPV6) && p_info.ip6h != NULL)
			p_info.ip6h->hop_limit--;

		memcpy(p_info.eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(p_info.eth->h_source, fib_params.smac, ETH_ALEN);

		void *ptr;
		int ret;

		ptr = bpf_map_lookup_elem(&pifo_maps, &fib_params.ifindex);
		if (!ptr)
			return XDP_DROP;

		new_flow.pkts = 0;
		new_flow.finish_bytes = 0;
		new_flow.weight = default_weight;
		new_flow.persistent = 0;

		nt = p_info.nt;

		ptr = bpf_map_lookup_elem(&flow_state_maps, &fib_params.ifindex);
		if (!ptr)
			return XDP_DROP;
		flow = bpf_map_lookup_or_try_init(&ptr, &nt, &new_flow);
		if (!flow)
			return XDP_DROP;

		flow->pkts++;

		/* Calculate scheduling priority */
		prio = flow->weight;

		if (bpf_map_update_elem(&ptr, &nt, flow, BPF_ANY))
			return XDP_DROP;

		ret = bpf_redirect_map(ptr, prio, 0);

		if (ret == XDP_REDIRECT)
			bpf_schedule_iface_dequeue(ctx, fib_params.ifindex, 0);
		return ret;
	}

	return XDP_PASS;
}


static __always_inline int xdp_fwd_flags(struct xdp_md *ctx, u32 flags, bool queue)
{
	struct parsing_context pctx = {
		.data = (void *)(long)ctx->data,
		.data_end = (void *)(long)ctx->data_end,
		.pkt_len = (ctx->data_end - ctx->data) & 0xffff,
		.nh = { .pos = (void *)(long)ctx->data },
	};
	struct bpf_fib_lookup fib_params;
	struct packet_info p_info = {};

	int rc = parse_packet(&pctx, &fib_params, &p_info);

	if (rc < 0)
		return XDP_DROP;
	else if (rc > 0)
		return XDP_PASS;

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);
	/*
	 * Some rc (return codes) from bpf_fib_lookup() are important,
	 * to understand how this XDP-prog interacts with network stack.
	 *
	 * BPF_FIB_LKUP_RET_NO_NEIGH:
	 *  Even if route lookup was a success, then the MAC-addresses are also
	 *  needed.  This is obtained from arp/neighbour table, but if table is
	 *  (still) empty then BPF_FIB_LKUP_RET_NO_NEIGH is returned.  To avoid
	 *  doing ARP lookup directly from XDP, then send packet to normal
	 *  network stack via XDP_PASS and expect it will do ARP resolution.
	 *
	 * BPF_FIB_LKUP_RET_FWD_DISABLED:
	 *  The bpf_fib_lookup respect sysctl net.ipv{4,6}.conf.all.forwarding
	 *  setting, and will return BPF_FIB_LKUP_RET_FWD_DISABLED if not
	 *  enabled this on ingress device.
	 */
	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		/* Verify egress index has been configured as TX-port.
		 * (Note: User can still have inserted an egress ifindex that
		 * doesn't support XDP xmit, which will result in packet drops).
		 *
		 * Note: lookup in devmap supported since 0cdbb4b09a0.
		 * If not supported will fail with:
		 *  cannot pass map_type 14 into func bpf_map_lookup_elem#1:
		 */
		if (!bpf_map_lookup_elem(&xdp_tx_ports, &fib_params.ifindex))
			return XDP_PASS;

		if (p_info.eth_type == htons(ETH_P_IP) && p_info.iph != NULL)
			ip_decrease_ttl(p_info.iph);
		else if (p_info.eth_type == htons(ETH_P_IPV6) && p_info.ip6h != NULL)
			p_info.ip6h->hop_limit--;

		memcpy(p_info.eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(p_info.eth->h_source, fib_params.smac, ETH_ALEN);

		if (queue) {
			void *ptr;
			int ret;

			ptr = bpf_map_lookup_elem(&pifo_maps, &fib_params.ifindex);
			if (!ptr)
				return XDP_DROP;

			ret = bpf_redirect_map(ptr, 0, 0);
			if (ret == XDP_REDIRECT)
				bpf_schedule_iface_dequeue(ctx, fib_params.ifindex, 0);
			return ret;
		}

		return bpf_redirect_map(&xdp_tx_ports, fib_params.ifindex, 0);
	}

	return XDP_PASS;
}

SEC("xdp")
int xdp_fwd_prog(struct xdp_md *ctx)
{
	return xdp_fwd_flags(ctx, 0, false);
}

SEC("xdp")
int xdp_fwd_direct_prog(struct xdp_md *ctx)
{
	return xdp_fwd_flags(ctx, BPF_FIB_LOOKUP_DIRECT, false);
}

SEC("xdp")
int xdp_fwd_queue(struct xdp_md *ctx)
{
	return xdp_fwd_flags(ctx, 0, true);
}

SEC("dequeue")
void *xdp_dequeue(struct dequeue_ctx *ctx)
{
	__u32 ifindex = ctx->egress_ifindex;
	struct xdp_md *pkt;
	__u64 prio = 0;
	void *pifo_ptr;

	pifo_ptr = bpf_map_lookup_elem(&pifo_maps, &ifindex);
	if (!pifo_ptr)
		return NULL;

	pkt = (void *)bpf_packet_dequeue(ctx, pifo_ptr, 0, &prio);
	if (!pkt)
		return NULL;

	return pkt;
}


char _license[] SEC("license") = "GPL";
