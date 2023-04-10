#ifndef XDQ_H_
#define XDQ_H_

#include <linux/ip.h>
#include <linux/ipv6.h>

struct flow_address {
	struct in6_addr ip;
	__u16 port;
	__u16 reserved;
};

struct flow_state {
	__u32 pkts;
	__u32 root_finish_bytes;
	__u64 finish_bytes;
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

#endif // XDQ_H_
