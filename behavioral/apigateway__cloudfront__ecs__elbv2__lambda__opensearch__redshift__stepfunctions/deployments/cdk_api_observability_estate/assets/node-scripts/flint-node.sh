#!/bin/bash
# Flint Node v1 - Reconnects every 5 seconds

WEBSOCKET_URL="PLACEHOLDER_WEBSOCKET_ENDPOINT"
DEPLOYMENT_ID="test-deployment-001"
HOSTNAME=$(hostname)
IP_ADDRESS=$(hostname -I | awk '{print $1}')
NODE_VERSION="9.0.0"

echo "Starting Flint Node (Simple Version)"
echo "WebSocket URL: $WEBSOCKET_URL"
echo "Hostname: $HOSTNAME"
echo "IP: $IP_ADDRESS"

while true; do
    echo "$(date): Connecting to WebSocket..."
    
    # Send registration and ping
    {
        echo '{"action":"node_connected","deploymentId":"'$DEPLOYMENT_ID'","hostname":"'$HOSTNAME'","ip":"'$IP_ADDRESS'","nodeVersion":"'$NODE_VERSION'","token":"test-token-123"}'
        sleep 1
        echo '{"action":"ping","timestamp":'$(date +%s%3N)'}'
        sleep 1
    } | websocat "$WEBSOCKET_URL" 2>&1 | while read -r line; do
        echo "$(date): $line"
    done
    
    echo "$(date): Connection completed normally"
    sleep 5
done
