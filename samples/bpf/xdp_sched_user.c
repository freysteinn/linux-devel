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

#include "linux/if_link.h"
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdq.h"

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

const char *redir_prog_names[] = {
	"xdp_fifo",
	"xdp_sprio",
	"xdp_wfq",
};

const char *dequeue_prog_names[] = {
	"xdp_dequeue"
};

static int do_attach(int idx, int redir_prog_fd, int dequeue_prog_fd,
		     int redir_map_fd, int pifos_map_fd, int flows_map_fd,
		     int priority_queue_length_map_fd, int queue_length, const char *name)
{
	int err;

	if (pifos_map_fd > -1) {
		LIBBPF_OPTS(bpf_map_create_opts, map_opts, .map_extra = 8388608);
		char map_name[BPF_OBJ_NAME_LEN];
		int pifo_fd;

		snprintf(map_name, sizeof(map_name), "pifo_%d", idx);
		map_name[BPF_OBJ_NAME_LEN-1] = '\0';

		pifo_fd = bpf_map_create(BPF_MAP_TYPE_PIFO_XDP, map_name,
					 sizeof(__u32), sizeof(__u32), queue_length, &map_opts);
		if (pifo_fd < 0) {
			err = -errno;
			printf("ERROR: Couldn't create PIFO map: %s\n", strerror(-err));
			return err;
		}

		err = bpf_map_update_elem(pifos_map_fd, &idx, &pifo_fd, 0);
		if (err) {
			printf("ERROR: failed adding PIFO map for device %s\n", name);
			return err;
		}
	}

	if (flows_map_fd > -1) {
		LIBBPF_OPTS(bpf_map_create_opts, map_opts);
		char map_name[BPF_OBJ_NAME_LEN];
		int flow_fd;

		snprintf(map_name, sizeof(map_name), "flow_%d", idx);
		map_name[BPF_OBJ_NAME_LEN-1] = '\0';

		flow_fd = bpf_map_create(BPF_MAP_TYPE_HASH, map_name,
					 sizeof(struct network_tuple), sizeof(struct flow_state),
					 (1 << 14), &map_opts);

		if (flow_fd < 0) {
			err = -errno;
			printf("ERROR: Couldn't create flow map: %s\n", strerror(-err));
			return err;
		}

		err = bpf_map_update_elem(flows_map_fd, &idx, &flow_fd, 0);
		if (err) {
			printf("ERROR: failed adding flow map for device %s\n", name);
			return err;
		}
	}

	if (priority_queue_length_map_fd > -1) {
		LIBBPF_OPTS(bpf_map_create_opts, map_opts);
		char map_name[BPF_OBJ_NAME_LEN];
		int priority_queue_length_fd;

		snprintf(map_name, sizeof(map_name), "fqueue_length_%d", idx);
		map_name[BPF_OBJ_NAME_LEN-1] = '\0';

		priority_queue_length_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, map_name,
						 sizeof(__u32), sizeof(__u32),
						 8, &map_opts);

		if (priority_queue_length_fd < 0) {
			err = -errno;
			printf("ERROR: Couldn't create queue length map: %s\n", strerror(-err));
			return err;
		}

		err = bpf_map_update_elem(priority_queue_length_map_fd, &idx, &priority_queue_length_fd, 0);
		if (err) {
			printf("ERROR: failed adding queue length map for device %s\n", name);
			return err;
		}
	}

	if (dequeue_prog_fd > -1) {
		LIBBPF_OPTS(bpf_xdp_attach_opts, prog_opts, .old_prog_fd = -1);

		err = bpf_xdp_attach(idx, dequeue_prog_fd,
				     (XDP_FLAGS_DEQUEUE_MODE | XDP_FLAGS_REPLACE),
				     &prog_opts);
		if (err < 0) {
			printf("ERROR: failed to attach dequeue program to %s\n", name);
			return err;
		}
	}

	err = bpf_xdp_attach(idx, redir_prog_fd, xdp_flags, NULL);
	if (err < 0) {
		printf("ERROR: failed to attach redir program to %s\n", name);
		return err;
	}

	/* Adding ifindex as a possible egress TX port */
	err = bpf_map_update_elem(redir_map_fd, &idx, &idx, 0);
	if (err)
		printf("ERROR: failed using device %s as TX-port\n", name);

	return err;
}

static bool should_detach(__u32 prog_fd, const char **prog_names, int num_prog_names)
{
	struct bpf_prog_info prog_info = {};
	__u32 info_len = sizeof(prog_info);
	int err, i;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &info_len);
	if (err) {
		printf("ERROR: bpf_obj_get_info_by_fd failed (%s)\n",
		       strerror(errno));
		return false;
	}

	for (i = 0; i < num_prog_names; i++)
		if (!strcmp(prog_info.name, prog_names[i]))
			return true;

	return false;
}

static int do_detach(int ifindex, const char *ifname, const char *app_name)
{
	LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
	LIBBPF_OPTS(bpf_xdp_query_opts, query_opts);
	int prog_fd, err = 1;
	__u32 curr_prog_id;

	if (bpf_xdp_query(ifindex, xdp_flags, &query_opts)) {
		printf("ERROR: bpf_xdp_query_id failed (%s)\n",
		       strerror(errno));
		return err;
	}

	curr_prog_id = xdp_flags & XDP_FLAGS_SKB_MODE ? query_opts.skb_prog_id : query_opts.drv_prog_id;
	if (!curr_prog_id) {
		printf("ERROR: flags(0x%x) xdp prog is not attached to %s\n",
		       xdp_flags, ifname);
		return err;
	}

	prog_fd = bpf_prog_get_fd_by_id(curr_prog_id);
	if (prog_fd < 0) {
		printf("ERROR: bpf_prog_get_fd_by_id failed (%s)\n",
		       strerror(errno));
		return err;
	}

	if (!should_detach(prog_fd, redir_prog_names, ARRAY_SIZE(redir_prog_names))) {
		printf("ERROR: %s isn't attached to %s\n", app_name, ifname);
		close(prog_fd);
		return 1;
	}

	opts.old_prog_fd = prog_fd;
	err = bpf_xdp_detach(ifindex, xdp_flags, &opts);
	if (err < 0)
		printf("ERROR: failed to detach program from %s (%s)\n",
		       ifname, strerror(errno));

	close(prog_fd);

	if (query_opts.dequeue_prog_id) {
		prog_fd = bpf_prog_get_fd_by_id(query_opts.dequeue_prog_id);
		if (prog_fd < 0) {
			printf("ERROR: bpf_prog_get_fd_by_id failed (%s)\n",
			       strerror(errno));
			return err;
		}

		if (!should_detach(prog_fd, dequeue_prog_names, ARRAY_SIZE(dequeue_prog_names))) {
			close(prog_fd);
			return err;
		}

		opts.old_prog_fd = prog_fd;
		err = bpf_xdp_detach(ifindex,
				     (XDP_FLAGS_DEQUEUE_MODE | XDP_FLAGS_REPLACE),
				     &opts);
		if (err < 0)
			printf("ERROR: failed to detach dequeue program from %s (%s)\n",
			       ifname, strerror(errno));
	}

	/* todo: Remember to cleanup map, when adding use of shared map
	 *  bpf_map_delete_elem((map_fd, &idx);
	 */
	return err;
}

static void usage(const char *prog, FILE *out)
{
	fprintf(out,
		"usage: %s [OPTS] interface-list\n"
		"\nOPTS:\n"
		"    -d    detach program\n"
		"    -S    use skb-mode\n"
		"    -F    force loading prog\n"
		"    -Q    FIFO scheduler\n"
		"    -p    SPRIO scheduler\n"
		"    -W    WFQ scheduler rule\n"
		"    -w    add priority rule\n"
		"    -h    display this help and exit\n",
		prog);
}

int main(int argc, char **argv)
{
	int redir_prog_fd = -1;
	int dequeue_prog_fd = -1;
	int redir_map_fd = -1;
	int pifos_map_fd = -1;
	int flows_map_fd = -1;
	int priority_queue_length_map_fd = -1;

	const char *prog_name = "xdp_fifo";
	char filename[PATH_MAX];
	struct bpf_object *obj;
	int queue_length = 3000;
	int opt, i, idx, err;
	bool queue = false;
	int attach = 1;
	int has_flows = false;
	int has_priority_queue_length = false;
	int ret = 0;

	while ((opt = getopt(argc, argv, ":dDQSFWpwqh")) != -1) {
		switch (opt) {
		case 'd':
			attach = 0;
			break;
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'F':
			xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'Q':
			prog_name = "xdp_fifo";
			queue = true;
			break;
		case 'W':
			prog_name = "xdp_wfq";;
			has_flows = true;
			has_priority_queue_length = true;
			queue = true;
			break;
		case 'p':
			prog_name = "xdp_sprio";
			has_flows = true;
			has_priority_queue_length = true;
			queue = true;
			break;
		case 'w':
			// TODO add support for weight rules
			fprintf(stderr, "Weight rules not supported yet");
			return 1;
		case 'q':
			// TODO do proper error checking
			queue_length = atoi(optarg);
			break;
		case 'h':
			usage(basename(argv[0]), stdout);
			return 0;
		default:
			usage(basename(argv[0]), stderr);
			return 1;
		}
	}

	if (!(xdp_flags & XDP_FLAGS_SKB_MODE))
		xdp_flags |= XDP_FLAGS_DRV_MODE;

	if (optind == argc) {
		usage(basename(argv[0]), stderr);
		return 1;
	}

	if (attach) {
		snprintf(filename, sizeof(filename), "%s_%s_kern.o", argv[0], prog_name);

		if (access(filename, O_RDONLY) < 0) {
			printf("error accessing file %s: %s\n",
				filename, strerror(errno));
			return 1;
		}

		obj = bpf_object__open_file(filename, NULL);
		if (libbpf_get_error(obj)) {
			return 1;
		}

		err = bpf_object__load(obj);
		if (err) {
			printf("Does kernel support devmap lookup?\n");
			/* If not, the error message will be:
			 *  "cannot pass map_type 14 into func bpf_map_lookup_elem#1"
			 */
			return 1;
		}
		redir_prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj,
									   prog_name));
		if (redir_prog_fd < 0) {
			printf("program not found: %s\n", strerror(redir_prog_fd));
			return 1;
		}

		redir_map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj,
									"xdp_tx_ports"));
		if (redir_map_fd < 0) {
			printf("map not found: %s\n", strerror(redir_map_fd));
			return 1;
		}

		if (queue) {
			dequeue_prog_fd = bpf_program__fd(
				bpf_object__find_program_by_name(obj, "xdp_dequeue"));
			if (dequeue_prog_fd < 0) {
				printf("dequeue program not found: %s\n", strerror(dequeue_prog_fd));
				return 1;
			}
			pifos_map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "pifo_maps"));
			if (pifos_map_fd < 0) {
				printf("map not found: %s\n", strerror(-pifos_map_fd));
				return 1;
			}
		}

		if (has_flows) {
			flows_map_fd = bpf_map__fd(
				bpf_object__find_map_by_name(obj, "flow_state_maps"));
			if (flows_map_fd < 0) {
				printf("map not found: %s\n", strerror(-flows_map_fd));
				return 1;
			}
		}

		if (has_priority_queue_length) {
			priority_queue_length_map_fd = bpf_map__fd(
				bpf_object__find_map_by_name(obj, "priority_queue_length_maps"));
			if (priority_queue_length_map_fd < 0) {
				printf("map not found: %s\n", strerror(-priority_queue_length_map_fd));
				return 1;
			}
		}
	}

	for (i = optind; i < argc; ++i) {
		idx = if_nametoindex(argv[i]);
		if (!idx)
			idx = strtoul(argv[i], NULL, 0);

		if (!idx) {
			fprintf(stderr, "Invalid arg\n");
			return 1;
		}
		if (!attach) {
			err = do_detach(idx, argv[i], argv[0]);
			if (err)
				ret = err;
		} else {
			err = do_attach(idx, redir_prog_fd, dequeue_prog_fd,
					redir_map_fd, pifos_map_fd, flows_map_fd,
					priority_queue_length_map_fd,
					queue_length, argv[i]);
			if (err)
				ret = err;
		}
	}

	return ret;
}
