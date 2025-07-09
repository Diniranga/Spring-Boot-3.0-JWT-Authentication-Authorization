# 2FA/MFA Configuration Guide

## Overview

The application now supports configurable Two-Factor Authentication (2FA) that can be enabled or disabled globally using the `enable-2fa` configuration property in `application.yml`.

## Configuration

### Global 2FA Setting

In `src/main/resources/application.yml`:

```yaml
spring:
  application:
    security:
      enable-2fa: true  # Set to false to disable 2FA globally
```

- **`true`**: 2FA is enabled globally. Users with 2FA enabled will be required to provide a 2FA code during login.
- **`false`**: 2FA is disabled globally. All users can login without 2FA codes, regardless of their individual 2FA settings.

## How It Works

### 1. Global vs User-Level Control

The system has two levels of 2FA control:

1. **Global Level** (`enable-2fa` in application.yml): Controls whether 2FA is available for the entire application
2. **User Level** (`twoFactorEnabled` in User entity): Controls whether a specific user has 2FA enabled

### 2. Login Flow

When a user attempts to login:

1. **Credentials are validated** using Spring Security's AuthenticationManager
2. **Global 2FA check**: If `enable-2fa: false`, proceed with normal login
3. **User 2FA check**: If `enable-2fa: true` and user has `twoFactorEnabled: true`:
   - Generate a 6-digit 2FA code
   - Store code with 5-minute expiry
   - Return response with `twoFactorRequired: true`
4. **Normal login**: If `enable-2fa: false` or user doesn't have 2FA enabled:
   - Generate JWT tokens
   - Return response with `twoFactorRequired: false`

### 3. 2FA Verification Flow

1. User submits 2FA code via `/auth/verify-2fa`
2. System validates:
   - Global 2FA is enabled
   - User has 2FA enabled
   - Code is valid and not expired
3. If valid: Generate JWT tokens and complete login
4. If invalid: Return error message

## API Endpoints

### Authentication Endpoints

#### Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password"
}
```

**Response when 2FA required:**
```json
{
  "userEmail": "user@example.com",
  "userRole": "USER",
  "message": "2FA code sent. Please verify to complete login.",
  "twoFactorRequired": true,
  "accessToken": null,
  "refreshToken": null
}
```

**Response when 2FA not required:**
```json
{
  "accessToken": "jwt-token",
  "refreshToken": "refresh-token",
  "userEmail": "user@example.com",
  "userRole": "USER",
  "message": "Login successful",
  "twoFactorRequired": false
}
```

#### Verify 2FA Code
```http
POST /auth/verify-2fa
Content-Type: application/json

{
  "email": "user@example.com",
  "code": "123456"
}
```

#### Resend 2FA Code
```http
POST /auth/resend-2fa
Content-Type: application/json

{
  "email": "user@example.com"
}
```

### 2FA Management Endpoints

#### Enable 2FA for Current User
```http
POST /auth/enable-2fa
Authorization: Bearer <jwt-token>
```

#### Disable 2FA for Current User
```http
POST /auth/disable-2fa
Authorization: Bearer <jwt-token>
```

#### Get 2FA Status
```http
GET /auth/2fa-status
Authorization: Bearer <jwt-token>
```

**Response:**
```json
{
  "success": true,
  "userEmail": "user@example.com",
  "user2faEnabled": true,
  "global2faEnabled": true,
  "message": "2FA status retrieved successfully"
}
```

## Security Features

### 1. Code Generation
- 6-digit numeric codes using `SecureRandom`
- 5-minute expiry time
- Codes are cleared after successful verification

### 2. Validation
- Global 2FA setting must be enabled
- User must have 2FA enabled
- Code must match and not be expired
- Multiple validation layers prevent bypass

### 3. Error Handling
- Clear error messages for different failure scenarios
- Proper exception handling with appropriate HTTP status codes

## Testing

### Unit Tests
Run the 2FA-specific tests:
```bash
mvn test -Dtest=AuthenticationService2faTest
```

### Manual Testing

1. **Test with 2FA disabled globally:**
   ```yaml
   spring:
     application:
       security:
         enable-2fa: false
   ```
   - All users should login normally without 2FA codes

2. **Test with 2FA enabled globally:**
   ```yaml
   spring:
     application:
       security:
         enable-2fa: true
   ```
   - Users with 2FA enabled will require codes
   - Users without 2FA enabled will login normally

## Implementation Details

### Key Classes

1. **AuthenticationService**: Main service handling 2FA logic
2. **AuthenticationController**: REST endpoints for 2FA operations
3. **User Entity**: Contains 2FA-related fields:
   - `twoFactorEnabled`: Boolean flag for user-level 2FA
   - `twoFactorCode`: Current 2FA code
   - `twoFactorCodeExpiry`: Code expiry timestamp

### Configuration Injection

The `enable-2fa` property is injected using:
```java
@Value("${spring.application.security.enable-2fa}")
private boolean enable2fa;
```

### Code Generation

2FA codes are generated using:
```java
private String generateTwoFactorCode() {
    SecureRandom random = new SecureRandom();
    int code = 100000 + random.nextInt(900000); // 6-digit code
    return String.valueOf(code);
}
```

## Best Practices

1. **Environment-Specific Configuration**: Use different settings for dev/staging/production
2. **Gradual Rollout**: Enable 2FA for specific user groups first
3. **User Education**: Provide clear instructions for 2FA setup
4. **Fallback Options**: Consider backup codes for account recovery
5. **Monitoring**: Log 2FA-related events for security monitoring

## Troubleshooting

### Common Issues

1. **2FA codes not being generated**: Check if global 2FA is enabled
2. **Users can't enable 2FA**: Verify global setting is `true`
3. **Codes expire too quickly**: Adjust expiry time in code (currently 5 minutes)
4. **Login bypassing 2FA**: Ensure both global and user settings are correct

### Debug Logging

Enable debug logging to see 2FA-related events:
```yaml
logging:
  level:
    com.ead.posgateway.Auth.AuthenticationService: DEBUG
```

## Future Enhancements

1. **Email/SMS Integration**: Send codes via email or SMS
2. **TOTP Support**: Time-based One-Time Password (Google Authenticator)
3. **Backup Codes**: Generate backup codes for account recovery
4. **Rate Limiting**: Prevent brute force attacks on 2FA codes
5. **Remember Device**: Option to remember trusted devices 