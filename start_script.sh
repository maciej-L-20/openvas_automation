#!/bin/bash
echo "Restarting containers. This may take a while."
docker compose -f docker-compose.yml -p greenbone-community-edition up -d  # Start the containers using Docker Compose
sleep 60  # Wait 60 seconds to allow the containers to initialize
nohup python3 -u scanDaemon.py > daemon.log 2>&1 &  # Run the scan daemon script in the background and log output to daemon.log
echo "To create scans, run the user_app.py script (python3 user_app.py)"