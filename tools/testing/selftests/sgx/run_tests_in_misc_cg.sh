#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2023 Intel Corporation.

if ! lscgroup | grep -q "test/test1/test3$"; then
  echo "setting up cgroups for testing..."
  ./setup_epc_cg.sh
fi

test_cmd='./test_sgx'

timestamp=$(date +%Y%m%d_%H%M%S)

# Always use leaf node of misc cgroups so it works for both v1 and v2
# these may fail on OOM
nohup bash -c "cgexec -g misc:test/test1/test3 $test_cmd" >test1_1_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test1/test3 $test_cmd" >test1_2_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test1/test3 $test_cmd" >test1_3_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test1/test3 $test_cmd" >test1_4_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test1/test3 $test_cmd" >test1_5_$timestamp.log 2>&1 &

# These tests may timeout on oversubscribed tests on 4G EPC
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_1_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_2_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_3_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_4_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_5_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_6_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_7_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_8_$timestamp.log 2>&1 &

# this should work on 4G EPC
nohup bash -c "cgexec -g misc:test4 $test_cmd" >test4_1_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test4 $test_cmd" >test4_2_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test4 $test_cmd" >test4_3_$timestamp.log 2>&1 &
nohup bash -c "cgexec -g misc:test4 $test_cmd" >test4_4_$timestamp.log 2>&1 &
