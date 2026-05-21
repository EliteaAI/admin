#!/bin/bash

# Moderation API V2 Test Script
# Usage: ./test_moderation_api.sh

BASE_URL="http://localhost/admin/v2"
USER_ID=1
PROJECT_ID=1

echo "=== Moderation API V2 Tests ==="
echo ""

# Test 1: Create application access request
echo "1. Creating application access request..."
RESPONSE=$(curl -s -X POST "${BASE_URL}/moderation_status/administration/${USER_ID}" \
  -H "Content-Type: application/json" \
  -d '{
    "issue_type": "application_access_request",
    "project_id": '${PROJECT_ID}',
    "entity_id": 42,
    "description": "Need this application for data analysis work"
  }')
echo "$RESPONSE" | jq '.'
STATUS_ID=$(echo "$RESPONSE" | jq -r '.id')
echo "Created status ID: $STATUS_ID"
echo ""

# Test 2: Get user's requests
echo "2. Getting user's moderation requests..."
curl -s -X GET "${BASE_URL}/moderation_status/administration/${USER_ID}" | jq '.'
echo ""

# Test 3: List all requests with filters
echo "3. Listing pending application access requests..."
curl -s -X GET "${BASE_URL}/moderation_statuses/administration?status=pending&issue_type=application_access_request" | jq '.'
echo ""

# Test 4: Approve request (if STATUS_ID exists)
if [ -n "$STATUS_ID" ] && [ "$STATUS_ID" != "null" ]; then
  echo "4. Approving request ID: $STATUS_ID..."
  curl -s -X PUT "${BASE_URL}/moderation_status/administration/${USER_ID}" \
    -H "Content-Type: application/json" \
    -d '{
      "id": '${STATUS_ID}',
      "status": "approved"
    }' | jq '.'
  echo ""
fi

# Test 5: Create another request for rejection test
echo "5. Creating another request for rejection test..."
RESPONSE2=$(curl -s -X POST "${BASE_URL}/moderation_status/administration/${USER_ID}" \
  -H "Content-Type: application/json" \
  -d '{
    "issue_type": "application_access_request",
    "project_id": '${PROJECT_ID}',
    "entity_id": 43,
    "description": "Test request for rejection"
  }')
echo "$RESPONSE2" | jq '.'
STATUS_ID2=$(echo "$RESPONSE2" | jq -r '.id')
echo "Created status ID for rejection: $STATUS_ID2"
echo ""

# Test 6: Reject request with comment
if [ -n "$STATUS_ID2" ] && [ "$STATUS_ID2" != "null" ]; then
  echo "6. Rejecting request ID: $STATUS_ID2 with comment..."
  curl -s -X PUT "${BASE_URL}/moderation_status/administration/${USER_ID}" \
    -H "Content-Type: application/json" \
    -d '{
      "id": '${STATUS_ID2}',
      "status": "rejected",
      "rejection_comment": "Missing required documentation. Please provide: 1) Manager approval 2) Business justification"
    }' | jq '.'
  echo ""
fi

# Test 7: List approved requests
echo "7. Listing approved requests..."
curl -s -X GET "${BASE_URL}/moderation_statuses/administration?status=approved&limit=5" | jq '.'
echo ""

# Test 8: List rejected requests
echo "8. Listing rejected requests..."
curl -s -X GET "${BASE_URL}/moderation_statuses/administration?status=rejected&limit=5" | jq '.'
echo ""

# Test 9: Test validation error - missing required fields
echo "9. Testing validation error (missing required fields)..."
curl -s -X POST "${BASE_URL}/moderation_status/administration/${USER_ID}" \
  -H "Content-Type: application/json" \
  -d '{
    "issue_type": "application_access_request"
  }' | jq '.'
echo ""

# Test 10: Test validation error - invalid status
echo "10. Testing validation error (invalid status)..."
curl -s -X POST "${BASE_URL}/moderation_status/administration/${USER_ID}" \
  -H "Content-Type: application/json" \
  -d '{
    "issue_type": "test",
    "project_id": '${PROJECT_ID}',
    "description": "test",
    "status": "invalid_status"
  }' | jq '.'
echo ""

echo "=== Tests Complete ==="
