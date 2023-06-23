#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2023 Intel Corporation.

TEST_ROOT_CG=selftest
cgcreate -g misc:$TEST_ROOT_CG
if [ $? -ne 0 ]; then
    echo "# Please make sure cgroup-tools is installed, and misc cgroup is mounted."
    exit 1
fi
TEST_CG_SUB1=$TEST_ROOT_CG/test1
TEST_CG_SUB2=$TEST_ROOT_CG/test2
TEST_CG_SUB3=$TEST_ROOT_CG/test1/test3
TEST_CG_SUB4=$TEST_ROOT_CG/test4

cgcreate -g misc:$TEST_CG_SUB1
cgcreate -g misc:$TEST_CG_SUB2
cgcreate -g misc:$TEST_CG_SUB3
cgcreate -g misc:$TEST_CG_SUB4

# Default to V2
CG_ROOT=/sys/fs/cgroup
if [ ! -d "/sys/fs/cgroup/misc" ]; then
    echo "# cgroup V2 is in use."
else
    echo "# cgroup V1 is in use."
    CG_ROOT=/sys/fs/cgroup/misc
fi

CAPACITY=$(grep "sgx_epc" "$CG_ROOT/misc.capacity" | awk '{print $2}')
# This is below number of VA pages needed for enclave of capacity size. So
# should fail oversubscribed cases
SMALL=$(( CAPACITY / 512 ))

# At least load one enclave of capacity size successfully, maybe up to 4.
# But some may fail if we run more than 4 concurrent enclaves of capacity size.
LARGE=$(( SMALL * 4 ))

# Load lots of enclaves
LARGER=$CAPACITY
echo "# Setting up limits."
echo "sgx_epc $SMALL" | tee $CG_ROOT/$TEST_CG_SUB1/misc.max
echo "sgx_epc $LARGE" | tee $CG_ROOT/$TEST_CG_SUB2/misc.max
echo "sgx_epc $LARGER" | tee $CG_ROOT/$TEST_CG_SUB4/misc.max

timestamp=$(date +%Y%m%d_%H%M%S)

test_cmd="./test_sgx -t unclobbered_vdso_oversubscribed"

echo "# Start unclobbered_vdso_oversubscribed with SMALL limit, expecting failure..."
# Always use leaf node of misc cgroups so it works for both v1 and v2
# these may fail on OOM
cgexec -g misc:$TEST_CG_SUB3 $test_cmd >cgtest_small_$timestamp.log 2>&1 
if [[ $? -eq 0 ]]; then
    echo "# Fail on SMALL limit, not expecting any test passes."
    cgdelete -r -g misc:$TEST_ROOT_CG
    exit 1
else
    echo "# Test failed as expected."
fi

echo "# PASSED SMALL limit."

echo "# Start 4 concurrent unclobbered_vdso_oversubscribed tests with LARGE limit, expecting at least one success...."
pids=()
for i in {1..4}; do
    (
        cgexec -g misc:$TEST_CG_SUB2 $test_cmd >cgtest_large_positive_$timestamp.$i.log 2>&1
    ) &
    pids+=($!)
done

any_success=0
for pid in "${pids[@]}"; do
    wait "$pid"
    status=$?
    if [[ $status -eq 0 ]]; then
        any_success=1
	echo "# Process $pid returned successfully."
    fi
done

if [[ $any_success -eq 0 ]]; then
    echo "# Failed on LARGE limit positive testing, no test passes."
    cgdelete -r -g misc:$TEST_ROOT_CG
    exit 1
fi

echo "# PASSED LARGE limit positive testing."

echo "# Start 5 concurrent unclobbered_vdso_oversubscribed tests with LARGE limit, expecting at least one failure...."
pids=()
for i in {1..5}; do
    (
        cgexec -g misc:$TEST_CG_SUB2 $test_cmd >cgtest_large_negative_$timestamp.$i.log 2>&1
    ) &
    pids+=($!)
done

any_failure=0
for pid in "${pids[@]}"; do
    wait "$pid"
    status=$?
    if [[ $status -ne 0 ]]; then
	echo "# Process $pid returned failure."
        any_failure=1
    fi
done

if [[ $any_failure -eq 0 ]]; then
    echo "# Failed on LARGE limit negative testing, no test fails."
    cgdelete -r -g misc:$TEST_ROOT_CG
    exit 1
fi

echo "# PASSED LARGE limit negative testing."

echo "# Start 10 concurrent unclobbered_vdso_oversubscribed tests with LARGER limit, expecting no failure...."
pids=()
for i in {1..10}; do
    (
        cgexec -g misc:$TEST_CG_SUB4 $test_cmd >cgtest_larger_$timestamp.$i.log 2>&1
    ) &
    pids+=($!)
done

any_failure=0
for pid in "${pids[@]}"; do
    wait "$pid"
    status=$?
    if [[ $status -ne 0 ]]; then
	echo "# Process $pid returned failure."
        any_failure=1
    fi
done

if [[ $any_failure -ne 0 ]]; then
    echo "# Failed on LARGER limit, at least one test fails."
    cgdelete -r -g misc:$TEST_ROOT_CG
    exit 1
fi

echo "# PASSED LARGER limit tests."

echo "# PASSED ALL cgroup limit tests, cleanup cgroups..."
cgdelete -r -g misc:$TEST_ROOT_CG
echo "# done."
