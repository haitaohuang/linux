#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2023 Intel Corporation.

if [ -z "$1" ]
  then
    echo "No argument supplied, please provide 'max', 'current' or 'events'"
    exit 1
fi

watch -n 1 "find /sys/fs/cgroup -wholename */test*/misc.$1 -exec sh -c \
    'echo \"\$1:\"; cat \"\$1\"' _ {} \;"

