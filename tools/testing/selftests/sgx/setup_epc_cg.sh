#!/bin/sh
cgcreate -g misc:test
if [ $? -ne 0 ]; then
    echo "Please make sure cgroup-tools is installed, and misc cgroup is mounted."
    exit 1
fi
cgcreate -g misc:test/test1
cgcreate -g misc:test/test1/test3
cgcreate -g misc:test/test2
cgcreate -g misc:test4

LARGER=40960000000
LARGE=409600000
SMALL=4096000
if [ ! -d "/sys/fs/cgroup/misc" ]; then
    echo "cgroups v2 is in use. Only leaf nodes can run a process"
    echo "sgx_epc $SMALL" | tee /sys/fs/cgroup/test/test1/misc.max
    echo "sgx_epc $LARGE" | tee /sys/fs/cgroup/test/test2/misc.max
    echo "sgx_epc $LARGER" | tee /sys/fs/cgroup/test4/misc.max
else
    echo "cgroups v1 is in use."
    echo "sgx_epc $SMALL" | tee /sys/fs/cgroup/misc/test/test1/misc.max
    echo "sgx_epc $LARGE" | tee /sys/fs/cgroup/misc/test/test2/misc.max
    echo "sgx_epc $LARGER" | tee /sys/fs/cgroup/misc/test4/misc.max
fi
