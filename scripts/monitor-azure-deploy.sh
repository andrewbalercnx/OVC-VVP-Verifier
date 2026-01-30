#!/bin/bash
# Monitor Azure Container Apps deployment
# Usage: ./scripts/monitor-azure-deploy.sh [max_attempts]

AZURE_URL="https://vvp-verifier.wittytree-2a937ccd.uksouth.azurecontainerapps.io/healthz"
MAX_ATTEMPTS=${1:-10}
WAIT_SECONDS=30

echo "Monitoring Azure deployment at: $AZURE_URL"
echo "Max attempts: $MAX_ATTEMPTS, wait between: ${WAIT_SECONDS}s"
echo ""

for i in $(seq 1 $MAX_ATTEMPTS); do
    echo "Attempt $i/$MAX_ATTEMPTS: Checking Azure deployment..."
    response=$(curl -s "$AZURE_URL" 2>/dev/null)

    if [ "$response" = '{"ok":true}' ]; then
        echo ""
        echo "SUCCESS: Azure deployment is healthy!"
        echo "Response: $response"
        exit 0
    else
        echo "Status: ${response:-"No response"} (may still be deploying)"
        if [ $i -lt $MAX_ATTEMPTS ]; then
            echo "Waiting ${WAIT_SECONDS}s before next check..."
            sleep $WAIT_SECONDS
        fi
    fi
    echo ""
done

echo "TIMEOUT: Deployment not confirmed after $MAX_ATTEMPTS attempts"
echo "This may be normal if deployment takes longer than expected."
echo "Check Azure portal or GitHub Actions for deployment status."
exit 1
