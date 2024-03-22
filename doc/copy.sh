#!/bin/sh
# Create PID file
touch /var/run/lora-ws.pid
# Copy systemd service file
cp lora-ws.service /etc/systemd/system/
exit 0
