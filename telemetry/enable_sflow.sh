#!/bin/bash
# This configures Open vSwitch (s1) to sample 1 out of every 64 packets 
# and stream the telemetry to a collector listening on localhost port 6343.

echo "Enabling sFlow Telemetry on Switch s1..."
sudo ovs-vsctl -- --id=@sflow create sflow agent=s1 target=\"127.0.0.1:6343\" header=128 sampling=64 polling=10 -- set bridge s1 sflow=@sflow
echo "sFlow enabled successfully. Switch is now pushing telemetry data."