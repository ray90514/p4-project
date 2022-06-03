#!/bin/bash
for ((i = 0; i < $1; i++))
do
    hping3 $2 --udp -p 53 --data $(($RANDOM % 1500)) --count 1 --sign B -q
done
