/*
 * SO2 Kprobe based tracer - test suite
 *
 * Authors:
 *	Daniel Baluta <daniel.baluta@gmail.com>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>

#include "tracer.h"

void trace_process(int fd, pid_t pid)
{
	ioctl(fd, TRACER_ADD_PROCESS, pid);
}

void untrace_process(int fd, pid_t pid)
{

	ioctl(fd, TRACER_REMOVE_PROCESS, pid);
}

static void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s (add|remove) <pid>\n\n", argv0);
}

int main(int argc, char **argv)
{
	pid_t pid;

	if (argc != 3)
		usage(argv[0]);

	pid = atoi(argv[2]);

	int fd = open("/dev/tracer", O_RDWR);

	if (strcmp(argv[1], "add") == 0)
		trace_process(fd, pid);
	else if (strcmp(argv[1], "remove") == 0)
		untrace_process(fd, pid);
	else
		usage(argv[0]);

	close(fd);

	return 0;
}
