#!/bin/bash

# Script to verify your salt service deployment

# Initialize error counter
ERRORS=0

echo "🔍 Verifying Salt Service Deployment"
echo "===================================="

# Replace with your actual Railway URL
SERVICE_URL="https://salt.testnet.mysocial.network/"

echo ""
echo "1. Testing health endpoint..."
if ! curl -s "$SERVICE_URL/health" | jq .; then
    echo "❌ Health check failed"
    ((ERRORS++))
fi

echo ""
echo "2. Testing metrics endpoint..."
if ! curl -s "$SERVICE_URL/metrics" | jq .; then
    echo "❌ Metrics check failed"
    ((ERRORS++))
fi

echo ""
echo "3. To check if migrations ran, look for this in your Railway logs:"
echo "   - 'Database migrations completed'"
echo "   - 'Starting server on 0.0.0.0:3000'"
echo ""
echo "4. To verify database tables exist, you can:"
echo "   - Use Railway's database query interface"
echo "   - Run: SELECT user_identifier, address FROM wallet_vaults LIMIT 1;"
echo "   - Confirm user_salts and salt_audit_log are gone."

# Exit with status code based on errors
if [ $ERRORS -eq 0 ]; then
    echo -e "\n✅ All tests passed!"
    exit 0
else
    echo -e "\n❌ $ERRORS test(s) failed!"
    exit 1
fi