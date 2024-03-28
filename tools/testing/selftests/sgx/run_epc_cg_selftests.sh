##!/usr/bin/env sh
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
# We will only set limit in test1 and run tests in test3
TEST_CG_SUB3=$TEST_ROOT_CG/test1/test3
TEST_CG_SUB4=$TEST_ROOT_CG/test4

cgcreate -g misc:$TEST_CG_SUB1
cgcreate -g misc:$TEST_CG_SUB2
cgcreate -g misc:$TEST_CG_SUB3
cgcreate -g misc:$TEST_CG_SUB4

# Default to V2
CG_MISC_ROOT=/sys/fs/cgroup
CG_MEM_ROOT=/sys/fs/cgroup
CG_V1=0
if [ ! -d "/sys/fs/cgroup/misc" ]; then
    echo "# cgroup V2 is in use."
else
    echo "# cgroup V1 is in use."
    CG_MISC_ROOT=/sys/fs/cgroup/misc
    CG_MEM_ROOT=/sys/fs/cgroup/memory
    CG_V1=1
fi

CAPACITY=$(grep "sgx_epc" "$CG_MISC_ROOT/misc.capacity" | awk '{print $2}')
# This is below number of VA pages needed for enclave of capacity size. So
# should fail oversubscribed cases
SMALL=$(( CAPACITY / 512 ))

# At least load one enclave of capacity size successfully, maybe up to 4.
# But some may fail if we run more than 4 concurrent enclaves of capacity size.
LARGE=$(( SMALL * 4 ))

# Load lots of enclaves
LARGER=$CAPACITY
echo "# Setting up limits."
echo "sgx_epc $SMALL" > $CG_MISC_ROOT/$TEST_CG_SUB1/misc.max
echo "sgx_epc $LARGE" >  $CG_MISC_ROOT/$TEST_CG_SUB2/misc.max
echo "sgx_epc $LARGER" > $CG_MISC_ROOT/$TEST_CG_SUB4/misc.max

timestamp=$(date +%Y%m%d_%H%M%S)

test_cmd="./test_sgx -t unclobbered_vdso_oversubscribed"

wait_check_process_status() {
    pid=$1
    check_for_success=$2  # If 1, check for success;
                                # If 0, check for failure
    wait "$pid"
    status=$?

    if [ $check_for_success -eq 1 ] && [ $status -eq 0 ]; then
        echo "# Process $pid succeeded."
        return 0
    elif [ $check_for_success -eq 0 ] && [ $status -ne 0 ]; then
        echo "# Process $pid returned failure."
        return 0
    fi
    return 1
}

wait_and_detect_for_any() {
    check_for_success=$1  # If 1, check for success;
                                # If 0, check for failure
    shift
    detected=1 # 0 for success detection

    for pid in $@; do
        if wait_check_process_status "$pid" "$check_for_success"; then
            detected=0
            # Wait for other processes to exit
        fi
    done

    return $detected
}

echo "# Start unclobbered_vdso_oversubscribed with SMALL limit, expecting failure..."
# Always use leaf node of misc cgroups so it works for both v1 and v2
# these may fail on OOM
cgexec -g misc:$TEST_CG_SUB3 $test_cmd >cgtest_small_$timestamp.log 2>&1
if [ $? -eq 0 ]; then
    echo "# Fail on SMALL limit, not expecting any test passes."
    cgdelete -r -g misc:$TEST_ROOT_CG
    exit 1
else
    echo "# Test failed as expected."
fi

echo "# PASSED SMALL limit."

echo "# Start 4 concurrent unclobbered_vdso_oversubscribed tests with LARGE limit,
        expecting at least one success...."

pids=""
for i in 1 2 3 4; do
    (
        cgexec -g misc:$TEST_CG_SUB2 $test_cmd >cgtest_large_positive_$timestamp.$i.log 2>&1
    ) &
    pids="$pids $!"
done


if wait_and_detect_for_any 1 "$pids"; then
    echo "# PASSED LARGE limit positive testing."
else
    echo "# Failed on LARGE limit positive testing, no test passes."
    cgdelete -r -g misc:$TEST_ROOT_CG
    exit 1
fi

echo "# Start 5 concurrent unclobbered_vdso_oversubscribed tests with LARGE limit,
        expecting at least one failure...."
pids=""
for i in 1 2 3 4 5; do
    (
        cgexec -g misc:$TEST_CG_SUB2 $test_cmd >cgtest_large_negative_$timestamp.$i.log 2>&1
    ) &
    pids="$pids $!"
done

if wait_and_detect_for_any 0 "$pids"; then
    echo "# PASSED LARGE limit negative testing."
else
    echo "# Failed on LARGE limit negative testing, no test fails."
    cgdelete -r -g misc:$TEST_ROOT_CG
    exit 1
fi

echo "# Start 8 concurrent unclobbered_vdso_oversubscribed tests with LARGER limit,
        expecting no failure...."
pids=""
for i in 1 2 3 4 5 6 7 8; do
    (
        cgexec -g misc:$TEST_CG_SUB4 $test_cmd >cgtest_larger_$timestamp.$i.log 2>&1
    ) &
    pids="$pids $!"
done

if wait_and_detect_for_any 0 "$pids"; then
    echo "# Failed on LARGER limit, at least one test fails."
    cgdelete -r -g misc:$TEST_ROOT_CG
    exit 1
else
    echo "# PASSED LARGER limit tests."
fi

echo "# Start 8 concurrent unclobbered_vdso_oversubscribed tests with LARGER limit,
      randomly kill one, expecting no failure...."
pids=""
for i in 1 2 3 4 5 6 7 8; do
    (
        cgexec -g misc:$TEST_CG_SUB4 $test_cmd >cgtest_larger_kill_$timestamp.$i.log 2>&1
    ) &
    pids="$pids $!"
done
random_number=$(awk 'BEGIN{srand();print int(rand()*10)}')
sleep $((random_number + 5))

# Randomly select a PID to kill
RANDOM_INDEX=$(awk 'BEGIN{srand();print int(rand()*8)}')
counter=0
for pid in $pids; do
    if [ "$counter" -eq "$RANDOM_INDEX" ]; then
        PID_TO_KILL=$pid
        break
    fi
    counter=$((counter + 1))
done

kill $PID_TO_KILL
echo "# Killed process with PID: $PID_TO_KILL"

any_failure=0
for pid in $pids; do
    wait "$pid"
    status=$?
    if [ "$pid" != "$PID_TO_KILL" ]; then
        if [ $status -ne 0 ]; then
	    echo "# Process $pid returned failure."
            any_failure=1
        fi
    fi
done

if [ $any_failure -ne 0 ]; then
    echo "# Failed on random killing, at least one test fails."
    cgdelete -r -g misc:$TEST_ROOT_CG
    exit 1
fi
echo "# PASSED LARGER limit test with a process randomly killed."

cgcreate -g memory:$TEST_CG_SUB2
if [ $? -ne 0 ]; then
    echo "# Failed creating memory controller."
    cgdelete -r -g misc:$TEST_ROOT_CG
    exit 1
fi
MEM_LIMIT_TOO_SMALL=$((CAPACITY - 2 * LARGE))

if [ $CG_V1 -eq 0 ]; then
    echo "$MEM_LIMIT_TOO_SMALL" > $CG_MEM_ROOT/$TEST_CG_SUB2/memory.max
else
    echo "$MEM_LIMIT_TOO_SMALL" > $CG_MEM_ROOT/$TEST_CG_SUB2/memory.limit_in_bytes
    echo "$MEM_LIMIT_TOO_SMALL" > $CG_MEM_ROOT/$TEST_CG_SUB2/memory.memsw.limit_in_bytes
fi

echo "# Start 4 concurrent unclobbered_vdso_oversubscribed tests with LARGE EPC limit,
        and too small RAM limit, expecting all failures...."
pids=""
for i in 1 2 3 4; do
    (
        cgexec -g memory:$TEST_CG_SUB2 -g misc:$TEST_CG_SUB2 $test_cmd \
               >cgtest_large_oom_$timestamp.$i.log 2>&1
    ) &
    pids="$pids $!"
done

if wait_and_detect_for_any 1 "$pids"; then
    echo "# Failed on tests with memcontrol, some tests did not fail."
    cgdelete -r -g misc:$TEST_ROOT_CG
    if [[ $CG_V1 -ne 0 ]]; then
        cgdelete -r -g memory:$TEST_ROOT_CG
    fi
    exit 1
else
    echo "# PASSED LARGE limit tests with memcontrol."
fi

sleep 2

USAGE=$(grep '^sgx_epc' "$CG_MISC_ROOT/$TEST_ROOT_CG/misc.current" | awk '{print $2}')
if [ "$USAGE" -ne 0 ]; then
    echo "# Failed: Final usage is $USAGE, not 0."
else
    echo "# PASSED leakage check."
    echo "# PASSED ALL cgroup limit tests, cleanup cgroups..."
fi
cgdelete -r -g misc:$TEST_ROOT_CG
if [ $CG_V1 -ne 0 ]; then
     cgdelete -r -g memory:$TEST_ROOT_CG
fi
echo "# done."
