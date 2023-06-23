#!/bin/bash

cmd='./test_sgx'
default_test="augment_via_eaccept_long"

# We use 'tail' to skip header lines and 'sed' to remove 'enclave' from the first non-header line.
# stderr is redirected to stdout with '2>&1'.
list=$($cmd -l 2>&1 | tail -n +4 | sed '0,/^enclave/ s/^enclave//' | sed 's/^ *//')

IFS=$'\n' read -d '' -r -a lines <<< "$list"
lines=("all" "${lines[@]}")

echo "Available tests:"
for i in "${!lines[@]}"; do
  # Check if the current line is the default test
  if [[ ${lines[$i]} == *"$default_test"* ]]; then
    echo "$((i)). ${lines[$i]} (default)"
  else
    echo "$((i)). ${lines[$i]}"
  fi
done

echo "Please enter the number of the test you want to run (or press enter for the default test):"
read choice

# If the user does not input anything, use the default test
if [ -z "$choice" ]; then
  testname="$default_test"
else
  testname="${lines[$choice]}"
fi

# If the user chooses "all", run the command without options
if [ "$testname" == "all" ]; then
  test_cmd="$cmd"
else
  test_cmd="$cmd -t $testname"
fi


# Alway use leaf node of misc cgroups so it works for both v1 and v2
# these may fail on OOM
nohup bash -c "cgexec -g misc:test/test1/test3 $test_cmd" >test1_1.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test1/test3 $test_cmd" >test1_2.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test1/test3 $test_cmd" >test1_3.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test1/test3 $test_cmd" >test1_4.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test1/test3 $test_cmd" >test1_5.log 2>&1 &

# These tests may timeout on oversubscribed tests on 4G EPC
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_1.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_2.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_3.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_4.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_5.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_6.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_7.log 2>&1 &
nohup bash -c "cgexec -g misc:test/test2 $test_cmd" >test2_8.log 2>&1 &

# this should work on 4G EPC
nohup bash -c "cgexec -g misc:test4 $test_cmd" >test4_1.log 2>&1 &
nohup bash -c "cgexec -g misc:test4 $test_cmd" >test4_2.log 2>&1 &
nohup bash -c "cgexec -g misc:test4 $test_cmd" >test4_3.log 2>&1 &
nohup bash -c "cgexec -g misc:test4 $test_cmd" >test4_4.log 2>&1 &
