#!/bin/bash
# 定义要启动的进程数量
PROCESSES=10

# 定义要执行的 Python 脚本
PY_SCRIPT=get_many_sui.py

# 循环启动进程，直到所有任务都完成
COUNT=0
while [ $COUNT -lt ${PROCESSES} ]
do
	  python ${PY_SCRIPT} > test_${COUNT} &
	    COUNT=$(expr $COUNT + 1)
    done

    # 等待所有进程完成
    wait

    echo "All tasks completed."
