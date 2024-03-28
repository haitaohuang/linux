#!/usr/bin/env sh
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2023, 2024 Intel Corporation.

TEST_ROOT_CG=selftest
TEST_CG_SUB1=$TEST_ROOT_CG/test1
TEST_CG_SUB2=$TEST_ROOT_CG/test2
# We will only set limit in test1 and run tests in test3
TEST_CG_SUB3=$TEST_ROOT_CG/test1/test3
TEST_CG_SUB4=$TEST_ROOT_CG/test4

# Cgroup v2 only
CG_ROOT=/sys/fs/cgroup
mkdir -p $CG_ROOT/$TEST_CG_SUB1
mkdir -p $CG_ROOT/$TEST_CG_SUB2
mkdir -p $CG_ROOT/$TEST_CG_SUB3
mkdir -p $CG_ROOT/$TEST_CG_SUB4

# Turn on misc and memory controller in non-leaf nodes
echo "+misc" >  $CG_ROOT/cgroup.subtree_control
echo "+memory" > $CG_ROOT/cgroup.subtree_control
echo "+misc" >  $CG_ROOT/$TEST_ROOT_CG/cgroup.subtree_control
echo "+memory" > $CG_ROOT/$TEST_ROOT_CG/cgroup.subtree_control
echo "+misc" >  $CG_ROOT/$TEST_CG_SUB1/cgroup.subtree_control

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
echo "sgx_epc $SMALL" > $CG_ROOT/$TEST_CG_SUB1/misc.max
echo "sgx_epc $LARGE" >  $CG_ROOT/$TEST_CG_SUB2/misc.max
echo "sgx_epc $LARGER" > $CG_ROOT/$TEST_CG_SUB4/misc.max

if [ $? -ne 0 ]; then
    echo "# Failed setting up misc limits, make sure misc cgroup is mounted."
    exit 1
fi

clean_up()
{
    sleep 2
    rmdir $CG_ROOT/$TEST_CG_SUB2
    rmdir $CG_ROOT/$TEST_CG_SUB3
    rmdir $CG_ROOT/$TEST_CG_SUB4
    rmdir $CG_ROOT/$TEST_CG_SUB1
    rmdir $CG_ROOT/$TEST_ROOT_CG
}

timestamp=$(date +%Y%m%d_%H%M%S)

test_cmd="./test_sgx -t unclobbered_vdso_oversubscribed"

# Wait for a process and check for expected exit status.
#
# Arguments:
#	$1 - the pid of the process to wait and check.
#	$2 - 1 if expecting success, 0 for failure.
#
# Return:
#	0 if the exit status of the process matches the expectation.
#	1 otherwise.
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

# Wait for a set of processes and check for expected exit status
#
# Arguments:
#	$1 - 1 if expecting success, 0 for failure.
#	remaining args - The pids of the processes
#
# Return:
#	0 if exit status of any process matches the expectation.
#	1 otherwise.
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
./ash_cgexec.sh $TEST_CG_SUB3 $test_cmd >cgtest_small_$timestamp.log 2>&1
if [ $? -eq 0 ]; then
    echo "# Fail on SMALL limit, not expecting any test passes."
    clean_up
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
        ./ash_cgexec.sh $TEST_CG_SUB2 $test_cmd >cgtest_large_positive_$timestamp.$i.log 2>&1
    ) &
    pids="$pids $!"
done


if wait_and_detect_for_any 1 "$pids"; then
    echo "# PASSED LARGE limit positive testing."
else
    echo "# Failed on LARGE limit positive testing, no test passes."
    clean_up
    exit 1
fi

echo "# Start 5 concurrent unclobbered_vdso_oversubscribed tests with LARGE limit,
        expecting at least one failure...."
pids=""
for i in 1 2 3 4 5; do
    (
        ./ash_cgexec.sh $TEST_CG_SUB2 $test_cmd >cgtest_large_negative_$timestamp.$i.log 2>&1
    ) &
    pids="$pids $!"
done

if wait_and_detect_for_any 0 "$pids"; then
    echo "# PASSED LARGE limit negative testing."
else
    echo "# Failed on LARGE limit negative testing, no test fails."
    clean_up
    exit 1
fi

echo "# Start 8 concurrent unclobbered_vdso_oversubscribed tests with LARGER limit,
        expecting no failure...."
pids=""
for i in 1 2 3 4 5 6 7 8; do
    (
        ./ash_cgexec.sh $TEST_CG_SUB4 $test_cmd >cgtest_larger_$timestamp.$i.log 2>&1
    ) &
    pids="$pids $!"
done

if wait_and_detect_for_any 0 "$pids"; then
    echo "# Failed on LARGER limit, at least one test fails."
    clean_up
    exit 1
else
    echo "# PASSED LARGER limit tests."
fi

echo "# Start 8 concurrent unclobbered_vdso_oversubscribed tests with LARGER limit,
      randomly kill one, expecting no failure...."
pids=""
for i in 1 2 3 4 5 6 7 8; do
    (
        ./ash_cgexec.sh $TEST_CG_SUB4 $test_cmd >cgtest_larger_kill_$timestamp.$i.log 2>&1
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
    clean_up
    exit 1
fi
echo "# PASSED LARGER limit test with a process randomly killed."

mkdir -p $CG_ROOT/$TEST_CG_SUB2
if [ $? -ne 0 ]; then
    echo "# Failed creating memory controller."
    clean_up
    exit 1
fi
MEM_LIMIT_TOO_SMALL=$((CAPACITY - 2 * LARGE))

echo "$MEM_LIMIT_TOO_SMALL" > $CG_ROOT/$TEST_CG_SUB2/memory.max

echo "# Start 4 concurrent unclobbered_vdso_oversubscribed tests with LARGE EPC limit,
        and too small RAM limit, expecting all failures...."
# Ensure swapping off
swapoff -a
pids=""
for i in 1 2 3 4; do
    (
        ./ash_cgexec.sh $TEST_CG_SUB2 $test_cmd >cgtest_large_oom_$timestamp.$i.log 2>&1
    ) &
    pids="$pids $!"
done

if wait_and_detect_for_any 1 "$pids"; then
    echo "# Failed on tests with memcontrol, some tests did not fail."
    clean_up
    swapon -a
    exit 1
else
    swapon -a
    echo "# PASSED LARGE limit tests with memcontrol."
fi

sleep 2

USAGE=$(grep '^sgx_epc' "$CG_ROOT/$TEST_ROOT_CG/misc.current" | awk '{print $2}')
if [ "$USAGE" -ne 0 ]; then
    echo "# Failed: Final usage is $USAGE, not 0."
else
    echo "# PASSED leakage check."
    echo "# PASSED ALL cgroup limit tests, cleanup cgroups..."
fi
clean_up
echo "# done."
