#!/bin/bash

# JWT Authentication API Testing Script
# Make sure the application is running on http://localhost:8080

BASE_URL="http://localhost:8080"
ADMIN_EMAIL="admin@gmail.com"
ADMIN_PASSWORD="root"
USER_EMAIL="user@gmail.com"
USER_PASSWORD="root"

echo "🚀 JWT Authentication API Testing Script"
echo "========================================"

# Function to extract token from response
extract_token() {
    echo $1 | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4
}

# Function to print response
print_response() {
    echo "Response: $1"
    echo "----------------------------------------"
}

# 1. Test public endpoint
echo "1. Testing public endpoint..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/public")
print_response "$RESPONSE"

# 2. Test rate limit endpoint
echo "2. Testing rate limit endpoint..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/test-rate-limit")
print_response "$RESPONSE"

# 2.5. Test HTTPS configuration
echo "2.5. Testing HTTPS configuration..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/test-https")
print_response "$RESPONSE"

# 3. Test admin login
echo "3. Testing admin login..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"$ADMIN_EMAIL\",
        \"password\": \"$ADMIN_PASSWORD\"
    }")
print_response "$LOGIN_RESPONSE"

# Extract admin token
ADMIN_TOKEN=$(extract_token "$LOGIN_RESPONSE")
echo "Admin token: ${ADMIN_TOKEN:0:50}..."

# 4. Test user login
echo "4. Testing user login..."
USER_LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"$USER_EMAIL\",
        \"password\": \"$USER_PASSWORD\"
    }")
print_response "$USER_LOGIN_RESPONSE"

# Extract user token
USER_TOKEN=$(extract_token "$USER_LOGIN_RESPONSE")
echo "User token: ${USER_TOKEN:0:50}..."

# 5. Test authenticated endpoint with admin
echo "5. Testing authenticated endpoint with admin..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/authenticated" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
print_response "$RESPONSE"

# 6. Test admin-only endpoint
echo "6. Testing admin-only endpoint..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/admin-only" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
print_response "$RESPONSE"

# 7. Test user-only endpoint with admin (should work)
echo "7. Testing user-only endpoint with admin..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/user-only" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
print_response "$RESPONSE"

# 8. Test user-only endpoint with user
echo "8. Testing user-only endpoint with user..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/user-only" \
    -H "Authorization: Bearer $USER_TOKEN")
print_response "$RESPONSE"

# 9. Test admin-only endpoint with user (should fail)
echo "9. Testing admin-only endpoint with user (should fail)..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/admin-only" \
    -H "Authorization: Bearer $USER_TOKEN")
print_response "$RESPONSE"

# 10. Test permission-based endpoints
echo "10. Testing permission-based endpoints..."

echo "   - Testing USER:READ with admin..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/user-read" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
print_response "$RESPONSE"

echo "   - Testing ADMIN:READ with admin..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/admin-read" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
print_response "$RESPONSE"

echo "   - Testing USER:READ with user..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/user-read" \
    -H "Authorization: Bearer $USER_TOKEN")
print_response "$RESPONSE"

echo "   - Testing ADMIN:READ with user (should fail)..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/admin-read" \
    -H "Authorization: Bearer $USER_TOKEN")
print_response "$RESPONSE"

# 11. Test current user info
echo "11. Testing current user info..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/current-user-info" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
print_response "$RESPONSE"

# 12. Test verify authentication
echo "12. Testing verify authentication..."
RESPONSE=$(curl -s -X POST "$BASE_URL/auth/verify-authentication" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
print_response "$RESPONSE"

# 13. Test token validation
echo "13. Testing token validation..."
RESPONSE=$(curl -s -X POST "$BASE_URL/auth/validateToken" \
    -H "Content-Type: application/json" \
    -d "{
        \"token\": \"$ADMIN_TOKEN\",
        \"email\": \"$ADMIN_EMAIL\"
    }")
print_response "$RESPONSE"

# 14. Test logout
echo "14. Testing logout..."
RESPONSE=$(curl -s -X POST "$BASE_URL/auth/logout" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
print_response "$RESPONSE"

# 15. Test access with logged out token (should fail)
echo "15. Testing access with logged out token (should fail)..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/authenticated" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
print_response "$RESPONSE"

# 16. Test error handling
echo "16. Testing error handling..."
RESPONSE=$(curl -s -X POST "$BASE_URL/test/test-error")
print_response "$RESPONSE"

# 17. Test invalid token
echo "17. Testing invalid token..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/authenticated" \
    -H "Authorization: Bearer invalid_token_here")
print_response "$RESPONSE"

# 18. Test access without token
echo "18. Testing access without token..."
RESPONSE=$(curl -s -X GET "$BASE_URL/test/authenticated")
print_response "$RESPONSE"

# 19. Test HTTPS configuration management (Admin only)
echo "19. Testing HTTPS configuration management..."
RESPONSE=$(curl -s -X GET "$BASE_URL/config/security/https-status" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
print_response "$RESPONSE"

echo "✅ Testing completed!"
echo ""
echo "📋 Summary:"
echo "- Public endpoints should work without authentication"
echo "- Admin can access all endpoints"
echo "- User can access user endpoints but not admin endpoints"
echo "- Invalid/expired tokens should be rejected"
echo "- Logout should invalidate tokens"
echo "- Rate limiting should be active"
echo "- Error handling should provide consistent responses" 