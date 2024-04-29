#!/usr/bin/env sh

insmod tracer.ko
pid=$(ps | grep syslogd | sed -n 's/^ *//;s/ .*$//; 1p')
./add add $pid
