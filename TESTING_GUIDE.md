# Testing Guide

## 🧪 **Overview**

This guide explains how to test the Spring Boot JWT Authentication and Authorization application, including both unit tests and integration tests.

## 📋 **Test Classes**

### 1. **AuthenticationService2faTest.java**
- **Type**: Unit Tests
- **Purpose**: Tests 2FA/MFA functionality
- **Coverage**: 2FA configuration, user authentication, 2FA code generation

### 2. **PosGatewayApplicationTests.java**
- **Type**: Integration Tests
- **Purpose**: Tests application context loading
- **Coverage**: Spring Boot application startup, configuration loading

## 🚀 **Running Tests**

### **Prerequisites**
- Java 17 or higher
- Maven 3.6+
- MySQL database running (for integration tests)

### **1. Run All Tests**
```bash
mvn test
```

### **2. Run Specific Test Class**
```bash
# Run 2FA tests only
mvn test -Dtest=AuthenticationService2faTest

# Run application context tests only
mvn test -Dtest=PosGatewayApplicationTests
```

### **3. Run Specific Test Method**
```bash
# Run a specific test method
mvn test -Dtest=AuthenticationService2faTest#when2faDisabled_shouldLoginNormally
```

### **4. Run Tests with Coverage**
```bash
mvn clean test jacoco:report
```

## 📊 **Test Results**

### **Expected Output for All Tests**
```
[INFO] Tests run: 6, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

### **Test Breakdown**
- **AuthenticationService2faTest**: 5 tests
- **PosGatewayApplicationTests**: 1 test
- **Total**: 6 tests

## 🔍 **Test Details**

### **AuthenticationService2faTest.java**

#### **Test Scenarios:**

1. **`when2faDisabled_shouldLoginNormally`**
   - **Purpose**: Tests normal login when 2FA is globally disabled
   - **Expected**: User logs in normally without 2FA codes
   - **Verification**: JWT tokens generated, no 2FA required

2. **`when2faEnabledAndUserHas2fa_shouldRequire2faCode`**
   - **Purpose**: Tests 2FA flow when both global and user 2FA are enabled
   - **Expected**: 2FA code generated, login requires verification
   - **Verification**: 2FA code sent, `twoFactorRequired: true`

3. **`when2faEnabledButUserDoesNotHave2fa_shouldLoginNormally`**
   - **Purpose**: Tests login when global 2FA is enabled but user doesn't have 2FA
   - **Expected**: User logs in normally (2FA is optional per user)
   - **Verification**: JWT tokens generated, no 2FA required

4. **`whenGlobal2faDisabled_shouldNotAllowEnablingUser2fa`**
   - **Purpose**: Tests that users can't enable 2FA when globally disabled
   - **Expected**: Exception thrown when trying to enable 2FA
   - **Verification**: Proper error message, no database changes

5. **`whenGlobal2faEnabled_shouldAllowEnablingUser2fa`**
   - **Purpose**: Tests that users can enable 2FA when globally enabled
   - **Expected**: 2FA enabled successfully for user
   - **Verification**: Database updated, no exceptions

#### **Test Setup:**
```java
@Mock
private UserRepository userRepository;

@Mock
private AuthenticationManager authenticationManager;

@Mock
private JwtService jwtService;

@Mock
private TokenRepository tokenRepository;

@InjectMocks
private AuthenticationService authenticationService;
```

### **PosGatewayApplicationTests.java**

#### **Test Scenarios:**

1. **`contextLoads`**
   - **Purpose**: Tests that Spring Boot application context loads successfully
   - **Expected**: Application starts without errors
   - **Verification**: All beans created, database connected, security configured

#### **Test Setup:**
```java
@SpringBootTest
class PosGatewayApplicationTests {
    @Test
    void contextLoads() {
        // Spring Boot context loads successfully
    }
}
```

## 🛠️ **Test Configuration**

### **Test Properties**
Tests use the same `application.yml` configuration as the main application, but you can override properties for testing:

```yaml
# src/test/resources/application-test.yml
spring:
  datasource:
    url: jdbc:h2:mem:testdb  # Use in-memory database for tests
    driver-class-name: org.h2.Driver
  jpa:
    hibernate:
      ddl-auto: create-drop
```

### **Test Dependencies**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-test</artifactId>
    <scope>test</scope>
</dependency>
```

## 🔧 **Troubleshooting**

### **Common Issues:**

1. **Database Connection Errors**
   ```bash
   # Ensure MySQL is running
   mysql.server start
   
   # Or use H2 for tests
   mvn test -Dspring.profiles.active=test
   ```

2. **Port Conflicts**
   ```bash
   # Kill processes on port 8080
   lsof -ti:8080 | xargs kill -9
   ```

3. **Test Failures**
   ```bash
   # Run with debug output
   mvn test -X
   
   # Run specific test with debug
   mvn test -Dtest=AuthenticationService2faTest -Dspring.profiles.active=test
   ```

### **Test Logs**
Enable debug logging for tests:
```yaml
# src/test/resources/application-test.yml
logging:
  level:
    com.ead.posgateway: DEBUG
    org.springframework.security: DEBUG
```

## 📈 **Adding New Tests**

### **Unit Test Template**
```java
@Test
void testMethodName() {
    // Given
    // Setup test data and mocks
    
    // When
    // Execute the method being tested
    
    // Then
    // Verify the expected behavior
}
```

### **Integration Test Template**
```java
@SpringBootTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class NewIntegrationTest {
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Test
    void testEndpoint() {
        // Test REST endpoints
    }
}
```

## 🎯 **Test Best Practices**

1. **Use Descriptive Test Names**
   - Follow the pattern: `when[Condition]_should[ExpectedBehavior]`

2. **Arrange-Act-Assert Pattern**
   - **Arrange**: Set up test data and mocks
   - **Act**: Execute the method being tested
   - **Assert**: Verify the expected behavior

3. **Mock External Dependencies**
   - Database repositories
   - External services
   - Security components

4. **Test Edge Cases**
   - Invalid inputs
   - Error conditions
   - Boundary values

5. **Keep Tests Independent**
   - Each test should be self-contained
   - No dependencies between tests

## 📊 **Test Coverage**

### **Current Coverage Areas:**
- ✅ 2FA Configuration and Logic
- ✅ User Authentication Flow
- ✅ Application Context Loading
- ✅ Security Configuration

### **Areas for Additional Tests:**
- [ ] JWT Token Validation
- [ ] Rate Limiting
- [ ] Account Lockout
- [ ] Security Headers
- [ ] API Endpoints
- [ ] Error Handling

## 🚀 **Continuous Integration**

### **GitHub Actions Example**
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up JDK 17
        uses: actions/setup-java@v2
        with:
          java-version: '17'
      - name: Run tests
        run: mvn test
```

## 📝 **Test Documentation**

### **Running Tests in IDE**

#### **IntelliJ IDEA:**
1. Right-click on test class → "Run"
2. Right-click on test method → "Run"
3. Use Ctrl+Shift+F10 to run current test

#### **Eclipse:**
1. Right-click on test class → "Run As" → "JUnit Test"
2. Right-click on test method → "Run As" → "JUnit Test"

#### **VS Code:**
1. Install Java Test Runner extension
2. Click the test icon in the sidebar
3. Click the play button next to tests

### **Test Reports**
After running tests, view reports at:
- `target/surefire-reports/` - Test execution reports
- `target/site/jacoco/` - Code coverage reports (if using JaCoCo)

## 🎉 **Success Criteria**

Tests are considered successful when:
- ✅ All tests pass (0 failures, 0 errors)
- ✅ Test coverage is adequate (>80% recommended)
- ✅ Tests run in reasonable time (<30 seconds)
- ✅ No flaky tests (consistent results)
- ✅ Tests are maintainable and readable 