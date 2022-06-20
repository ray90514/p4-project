#!/bin/bash
for ((i = 0; i < $1; i++))
do
    hping3 $2 --data $(($RANDOM % 1500)) --count 1 --sign A -q -i u10
done
