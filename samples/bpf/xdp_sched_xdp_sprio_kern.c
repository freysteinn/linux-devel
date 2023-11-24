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

#include "xdq.h"

#define IPV6_FLOWINFO_MASK              cpu_to_be32(0x0FFFFFFF)

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} xdp_tx_ports SEC(".maps");


/* PIFOs */
struct pifo_map {
	__uint(type, BPF_MAP_TYPE_PIFO_XDP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1024);
	__uint(map_extra, 8192); /* range */
} pmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 64);
	__array(values, struct pifo_map);
} pifo_maps SEC(".maps");


/* Priority queue-lengths */
struct priority_queue_length_map  {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 8);
} pqlmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(int));
	__uint(max_entries, 64);
	__array(values, struct priority_queue_length_map);
} priority_queue_length_maps SEC(".maps");


/* Flow states */
struct flow_state_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct network_tuple));
	__uint(value_size, sizeof(struct flow_state));
	__uint(max_entries, 16384);
} fsmap SEC(".maps");

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

static __always_inline int parse_packet_fib(struct parsing_context *pctx,
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
		if (parse_udphdr(&pctx->nh, pctx->data_end, &p_info->udph) < 0)
			goto err;
		p_info->nt.saddr.port = p_info->udph->source;
		p_info->nt.daddr.port = p_info->udph->dest;
	}
	else if (p_info->ip_type == IPPROTO_TCP) {
		p_info->nt.proto = IPPROTO_TCP;
		if (parse_tcphdr(&pctx->nh, pctx->data_end, &p_info->tcph) < 0)
			goto err;
		p_info->nt.saddr.port = p_info->tcph->source;
		p_info->nt.saddr.port = p_info->tcph->dest;;
	}
out:
	return 0;
pass:
	return 1;
err:
	return -1;
}

/* This is a copy of the parse_packet_fib function without the fib lookups.
 * In the future there should only be one function without this duplicate code */
static __always_inline int parse_packet(struct parsing_context *pctx,
					struct packet_info *p_info)
{
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

	} else if (p_info->eth_type == bpf_htons(ETH_P_IPV6)) {
		p_info->ip_type = parse_ip6hdr(&pctx->nh, pctx->data_end, &p_info->ip6h);

		if (p_info->ip_type < 0)
			goto err;

		if (p_info->ip6h->hop_limit <= 1)
			goto pass;

		p_info->nt.ipv = 6;
 		p_info->nt.saddr.ip = p_info->ip6h->saddr;
		p_info->nt.daddr.ip = p_info->ip6h->daddr;

	} else {
		goto out;
	}

	/* Parse UDP and TCP headers */
	if (p_info->ip_type == IPPROTO_UDP) {
		p_info->nt.proto = IPPROTO_UDP;
		if (parse_udphdr(&pctx->nh, pctx->data_end, &p_info->udph) < 0)
			goto err;
		p_info->nt.saddr.port = p_info->udph->source;
		p_info->nt.daddr.port = p_info->udph->dest;
	}
	else if (p_info->ip_type == IPPROTO_TCP) {
		p_info->nt.proto = IPPROTO_TCP;
		if (parse_tcphdr(&pctx->nh, pctx->data_end, &p_info->tcph) < 0)
			goto err;
		p_info->nt.saddr.port = p_info->tcph->source;
		p_info->nt.saddr.port = p_info->tcph->dest;;
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
__u32 max_priority_queue_length = 333;
__u32 total_queue_length = 0;

__u32 cs0 = 2;
__u32 cs1 = 1;
__u32 cs2 = 0;


SEC("xdp")
int xdp_sprio(struct xdp_md *ctx)
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

	int rc = parse_packet_fib(&pctx, &fib_params, &p_info);

	if (rc < 0)
		return XDP_DROP;
	else if (rc > 0)
		return XDP_PASS;

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), false);
	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		void *pifo_nic_map;
		void *flow_nic_map;
		void *priority_queue_length_nic_map;
		__u32 *priority_queue_length;
		__u32 tos = 0x00;
		__u32 tos_idx = cs0;
		__u32 prio = 0;
		int ret;

		if (!bpf_map_lookup_elem(&xdp_tx_ports, &fib_params.ifindex))
			return XDP_PASS;

		if (p_info.eth_type == htons(ETH_P_IP) && p_info.iph != NULL)
			ip_decrease_ttl(p_info.iph);
		else if (p_info.eth_type == htons(ETH_P_IPV6) && p_info.ip6h != NULL)
			p_info.ip6h->hop_limit--;

		memcpy(p_info.eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(p_info.eth->h_source, fib_params.smac, ETH_ALEN);

		/* Lookup nic specific maps */
		pifo_nic_map = bpf_map_lookup_elem(&pifo_maps, &fib_params.ifindex);
		if (!pifo_nic_map)
			return XDP_DROP;

		flow_nic_map = bpf_map_lookup_elem(&flow_state_maps, &fib_params.ifindex);
		if (!flow_nic_map)
			return XDP_DROP;

		priority_queue_length_nic_map = bpf_map_lookup_elem(&priority_queue_length_maps,
								&fib_params.ifindex);
		if (!priority_queue_length_nic_map)
			return XDP_DROP;

		/* Create or update new flow state */
		new_flow.pkts = 0;

		nt = p_info.nt;

		flow = bpf_map_lookup_or_try_init(flow_nic_map, &nt, &new_flow);
		if (!flow)
			return XDP_DROP;

		/* Calculate flow priority */
		/* These are static for now */
		if (!p_info.iph)
			return XDP_DROP;

		tos = p_info.iph->tos;
		if (tos == 0x20)
			tos_idx = cs1;
		else if (tos == 0x40)
			tos_idx = cs2;

		/* Update priority queue length */
		priority_queue_length = bpf_map_lookup_elem(priority_queue_length_nic_map, &tos_idx);
		if (!priority_queue_length)
			return XDP_DROP;
		if ((*priority_queue_length + 1) > max_priority_queue_length)
			return XDP_DROP;
		*priority_queue_length += 1;

		/* Calculate PIFO priority */
		prio = tos_idx;

		// Update flow state
		flow->pkts++;

		// Update per device PIFO
		ret = bpf_redirect_map(pifo_nic_map, prio, 0);

		if (ret == XDP_REDIRECT)
			bpf_schedule_iface_dequeue(ctx, fib_params.ifindex, 0);
		return ret;
	}

	return XDP_PASS;
}

SEC("dequeue")
void *xdp_dequeue(struct dequeue_ctx *ctx)
{
	__u32 ifindex = ctx->egress_ifindex;
	struct xdp_md *pkt;
	struct parsing_context pctx;
	struct packet_info p_info = {0};
	struct network_tuple nt;
	struct flow_state *flow;
	void *priority_queue_length_nic_map;
	void *flow_nic_map;
	void *pifo_nic_map;
	__u32 tos_idx = cs0;
	__u32 *priority_queue_length;
	__u64 prio = 0;

	/* Dequeue packet */
	pifo_nic_map = bpf_map_lookup_elem(&pifo_maps, &ifindex);
	if (!pifo_nic_map)
		return NULL;

	pkt = (void *)bpf_packet_dequeue(ctx, pifo_nic_map, 0, &prio);
	if (!pkt)
		return NULL;

	/* Parse packet */
	pctx.data = (void *)(long) pkt->data;
	pctx.data_end = (void *)(long) pkt->data_end;
	pctx.nh.pos = (void *)(long) pkt->data;

	if (parse_packet(&pctx, &p_info) < 0)
		goto err;
	if (!p_info.iph)
		goto err;

	/* Lookup nic specific maps */
	flow_nic_map = bpf_map_lookup_elem(&flow_state_maps, &ifindex);
	if (!flow_nic_map)
		goto err;

	priority_queue_length_nic_map = bpf_map_lookup_elem(&priority_queue_length_maps, &ifindex);
	if (!priority_queue_length_nic_map)
		goto err;

	/* Update priority queue length */
	/* Hardcoded for now */
	if (p_info.iph->tos == 0x20)
		tos_idx = cs1;
	else if (p_info.iph->tos == 0x40)
		tos_idx = cs2;

	priority_queue_length = bpf_map_lookup_elem(priority_queue_length_nic_map, &tos_idx);
	if (!priority_queue_length)
		goto err;
	*priority_queue_length -= 1;

	/* Update flow state */
	nt = p_info.nt;
	flow = bpf_map_lookup_elem(flow_nic_map, &nt);
	if (!flow)
		goto err;
	flow->pkts--;

	return pkt;
err:
	if (pkt)
		bpf_packet_drop(ctx, pkt);
	return NULL;
}

char _license[] SEC("license") = "GPL";
