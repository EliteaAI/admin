# Moderation API V2 Tests

Test files for the Moderation API v2 endpoints.

## Files

- `moderation_api_tests.http` - HTTP REST client tests (VS Code REST Client, IntelliJ HTTP Client)
- `test_moderation_api.sh` - Automated bash script with curl commands

## Prerequisites

- Admin plugin running at `http://localhost`
- Valid user and project IDs (default: user_id=1, project_id=1)

## Using HTTP Test File

### VS Code
1. Install "REST Client" extension
2. Open `moderation_api_tests.http`
3. Click "Send Request" above any request
4. Update variables at the top:
   ```
   @user_id = 1
   @project_id = 1
   @status_id = 1
   ```

### IntelliJ/PyCharm
1. Open `moderation_api_tests.http`
2. Click the green play button next to any request
3. Update variables as needed

## Using Bash Script

```bash
# Run all tests
./test_moderation_api.sh

# Customize variables
BASE_URL="http://localhost/admin/v2" \
USER_ID=2 \
PROJECT_ID=1 \
./test_moderation_api.sh
```

## Test Scenarios

### Create Requests
- ✅ Create application access request
- ✅ Create feature request
- ✅ Create with metadata
- ✅ Validation errors

### Read Requests
- ✅ Get user's requests
- ✅ Filter by issue type
- ✅ Filter by project
- ✅ Filter by status
- ✅ Pagination
- ✅ Sorting

### Update Requests
- ✅ Approve request
- ✅ Reject with comment
- ✅ Update metadata
- ✅ Validation errors

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/moderation_status/administration/<user_id>` | Create request |
| GET | `/moderation_status/administration/<user_id>` | Get user's requests |
| PUT | `/moderation_status/administration/<user_id>` | Update request |
| GET | `/moderation_statuses/administration` | List all requests |

## Example Responses

### Create Request
```json
{
  "id": 1,
  "user_id": 1,
  "project_id": 1,
  "issue_type": "application_access_request",
  "entity_id": 42,
  "description": "Need this app for analysis",
  "status": "pending",
  "rejection_comment": null,
  "meta": {},
  "created_at": "2026-05-21T10:00:00",
  "updated_at": "2026-05-21T10:00:00"
}
```

### List Requests
```json
{
  "total": 10,
  "rows": [
    {
      "id": 1,
      "user_id": 1,
      "status": "pending",
      ...
    }
  ]
}
```

### Validation Error
```json
{
  "error": "Validation error",
  "details": [
    {
      "type": "missing",
      "loc": ["body", "description"],
      "msg": "Field required"
    }
  ]
}
```

## Common Issues

### 401 Unauthorized
- Ensure you have admin permissions
- Check authentication cookies/headers

### 404 Not Found
- Verify the endpoint URL is correct
- Ensure pylon_main is running

### 400 Validation Error
- Check all required fields are present
- Verify field types and constraints
- Status must be: pending/approved/rejected

## Use Cases

### Application Access Request Flow
1. User creates request → `status: "pending"`
2. Admin reviews → GET requests list
3. Admin approves → PUT with `status: "approved"`
4. OR Admin rejects → PUT with `status: "rejected"` + `rejection_comment`

### Feature Request Flow
1. User submits → `issue_type: "feature_request"`
2. Admin filters → GET with `issue_type` filter
3. Admin reviews and updates status
