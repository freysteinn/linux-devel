#!/bin/sh

# This script tests the list.ko kernel module.

# Load the module
insmod ./list.ko

ELEMENT_PREFIX="frey"


# Add elements to the list
printf "${0}: Adding elements to the end of the list\n"
for i in $(seq 1 5); do
    command="adde ${ELEMENT_PREFIX}${i}"
    echo "${0}: $command > /proc/list/management"
    echo "$command" > /proc/list/management
done
printf "${0}:Listing elements in the list\n"
diff /proc/list/preview adde.txt
if [ $? -eq 0 ]; then
    cat /proc/list/preview
fi
printf "\n\n"
sleep 0.5


# Add elements to the front of the list
printf "${0}: Adding elements to the front of the list\n"
for i in $(seq 1 5); do
    command="addf ${ELEMENT_PREFIX}${i}"
    echo "${0}: $command > /proc/list/management"
    echo "$command" > /proc/list/management
done
printf "${0}: Listing elements in the list\n"
diff /proc/list/preview addf.txt
if [ $? -eq 0 ]; then
    cat /proc/list/preview
fi
printf "\n\n"
sleep 0.5


# Delete one element from the list
printf "${0}: Deleting one element from the list\n"
command="delf ${ELEMENT_PREFIX}3"
echo "${0}: $command > /proc/list/management"
echo "$command" > /proc/list/management
printf "${0}: Listing elements in the list\n"
diff /proc/list/preview delf.txt
if [ $? -eq 0 ]; then
    cat /proc/list/preview
fi
printf "\n\n"
sleep 0.5


# Delete all elements of a specific type from the list
command="dela ${ELEMENT_PREFIX}4"
echo "${0}: $command > /proc/list/management"
echo "$command" > /proc/list/management
printf "${0}: Listing elements in the list\n"
diff /proc/list/preview dela.txt
if [ $? -eq 0 ]; then
    cat /proc/list/preview
fi
printf "\n\n"
sleep 0.5

# Test for errors
printf "${0}: Test for wrong command\n"
command="dele ${ELEMENT_PREFIX}1"
echo "${0}: $command > /proc/list/management"
echo "$command" > /proc/list/management
diff /proc/list/preview error_cmd.txt
sleep 0.5

command="del"
echo "${0}: $command > /proc/list/management"
echo "$command" > /proc/list/management
diff /proc/list/preview error_cmd.txt
sleep 0.5

# Test for buffer overflow
command=""
for i in $(seq 10000); do
    command="${command}A"
done
echo "${0}: $command > /proc/list/management"
echo "$command" > /proc/list/management
diff /proc/list/preview error_cmd.txt

command="addf "
for i in $(seq 4090); do
    command="${command}A"
done
command="${command}B"
echo "${0}: $command > /proc/list/management"
echo "$command" > /proc/list/management
diff /proc/list/preview error_cmd2.txt
printf "\n\n"
sleep 0.5

# Add multiple elements to the list
printf "${0}: Adding 5000 elements to the list\n"
for i in $(seq 1 5000); do
    command="adde ${ELEMENT_PREFIX}${i}"
    echo "$command" > /proc/list/management
done
diff /proc/list/preview adde_5000.txt

# Unload the kernel module
rmmod list
