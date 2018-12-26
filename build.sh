#!/bin/sh

# Step 1: Create *.json and *.p4info
p4c-bm2-ss --std p4-16 --target bmv2 --arch v1model -o zdf.json --p4runtime-file zdf.p4info --p4runtime-format text zdf.p4

# Step 2: Assign those deps to ../../lib/main.py
#       - topology.json
#       - *.p4.json
#       - "simple_switch_grpc"
sudo python ../../../utils/run_exercise.py \
    --topo topology.json \
    --switch_json zdf.json \
    --behavioral-exe simple_switch_grpc
