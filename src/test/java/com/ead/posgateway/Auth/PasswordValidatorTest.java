package com.ead.posgateway.Auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class PasswordValidatorTest {

    @InjectMocks
    private PasswordValidator passwordValidator;

    @BeforeEach
    void setUp() {
        // PasswordValidator is stateless, no setup needed
    }

    @Test
    void validatePassword_withValidPassword_shouldReturnValidResult() {
        // Given
        String validPassword = "StrongP@ss123";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(validPassword);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withNullPassword_shouldReturnInvalidResult() {
        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(null);

        // Then
        assertFalse(result.isValid());
        assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().contains("Password must be at least 8 characters long"));
    }

    @Test
    void validatePassword_withEmptyPassword_shouldReturnInvalidResult() {
        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword("");

        // Then
        assertFalse(result.isValid());
        assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().contains("Password must be at least 8 characters long"));
    }

    @Test
    void validatePassword_withShortPassword_shouldReturnInvalidResult() {
        // Given
        String shortPassword = "Abc1!";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(shortPassword);

        // Then
        assertFalse(result.isValid());
        assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().contains("Password must be at least 8 characters long"));
    }

    @Test
    void validatePassword_withoutUppercase_shouldReturnInvalidResult() {
        // Given
        String passwordWithoutUppercase = "strongp@ss123";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithoutUppercase);

        // Then
        assertFalse(result.isValid());
        assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().contains("Password must contain at least one uppercase letter"));
    }

    @Test
    void validatePassword_withoutLowercase_shouldReturnInvalidResult() {
        // Given
        String passwordWithoutLowercase = "STRONGP@SS123";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithoutLowercase);

        // Then
        assertFalse(result.isValid());
        assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().contains("Password must contain at least one lowercase letter"));
    }

    @Test
    void validatePassword_withoutDigit_shouldReturnInvalidResult() {
        // Given
        String passwordWithoutDigit = "StrongP@ss";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithoutDigit);

        // Then
        assertFalse(result.isValid());
        assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().contains("Password must contain at least one digit"));
    }

    @Test
    void validatePassword_withoutSpecialCharacter_shouldReturnInvalidResult() {
        // Given
        String passwordWithoutSpecialChar = "StrongPass123";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithoutSpecialChar);

        // Then
        assertFalse(result.isValid());
        assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().contains("Password must contain at least one special character"));
    }

    @Test
    void validatePassword_withMultipleErrors_shouldReturnAllErrors() {
        // Given
        String weakPassword = "weak";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(weakPassword);

        // Then
        assertFalse(result.isValid());
        assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().contains("Password must be at least 8 characters long"));
        assertTrue(result.getErrors().contains("Password must contain at least one uppercase letter"));
        assertTrue(result.getErrors().contains("Password must contain at least one digit"));
        assertTrue(result.getErrors().contains("Password must contain at least one special character"));
    }

    @Test
    void validatePassword_withCommonWeakPassword_shouldReturnInvalidResult() {
        // Given
        String commonPassword = "password123";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(commonPassword);

        // Then
        assertFalse(result.isValid());
        assertFalse(result.getErrors().isEmpty());
        assertTrue(result.getErrors().contains("Password must contain at least one uppercase letter"));
        assertTrue(result.getErrors().contains("Password must contain at least one special character"));
    }

    @Test
    void validatePassword_withValidComplexPassword_shouldReturnValidResult() {
        // Given
        String complexPassword = "MyStr0ngP@ssw0rd!";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(complexPassword);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithSpecialChars_shouldReturnValidResult() {
        // Given
        String passwordWithSpecialChars = "P@ssw0rd#123";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithSpecialChars);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithUnderscore_shouldReturnValidResult() {
        // Given
        String passwordWithUnderscore = "My_P@ss123";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithUnderscore);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithHyphen_shouldReturnValidResult() {
        // Given
        String passwordWithHyphen = "My-P@ss123";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithHyphen);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithExclamation_shouldReturnValidResult() {
        // Given
        String passwordWithExclamation = "MyP@ss123!";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithExclamation);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithQuestionMark_shouldReturnValidResult() {
        // Given
        String passwordWithQuestionMark = "MyP@ss123?";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithQuestionMark);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithDollarSign_shouldReturnValidResult() {
        // Given
        String passwordWithDollarSign = "MyP@ss123$";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithDollarSign);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithPercentSign_shouldReturnValidResult() {
        // Given
        String passwordWithPercentSign = "MyP@ss123%";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithPercentSign);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithAmpersand_shouldReturnValidResult() {
        // Given
        String passwordWithAmpersand = "MyP@ss123&";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithAmpersand);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithAsterisk_shouldReturnValidResult() {
        // Given
        String passwordWithAsterisk = "MyP@ss123*";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithAsterisk);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithPlusSign_shouldReturnValidResult() {
        // Given
        String passwordWithPlusSign = "MyP@ss123+";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithPlusSign);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithEqualsSign_shouldReturnValidResult() {
        // Given
        String passwordWithEqualsSign = "MyP@ss123=";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithEqualsSign);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithBrackets_shouldReturnValidResult() {
        // Given
        String passwordWithBrackets = "MyP@ss123[]";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithBrackets);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithBraces_shouldReturnValidResult() {
        // Given
        String passwordWithBraces = "MyP@ss123{}";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithBraces);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithParentheses_shouldReturnValidResult() {
        // Given
        String passwordWithParentheses = "MyP@ss123()";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithParentheses);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithPipe_shouldReturnValidResult() {
        // Given
        String passwordWithPipe = "MyP@ss123|";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithPipe);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithBackslash_shouldReturnValidResult() {
        // Given
        String passwordWithBackslash = "MyP@ss123\\";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithBackslash);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithForwardSlash_shouldReturnValidResult() {
        // Given
        String passwordWithForwardSlash = "MyP@ss123/";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithForwardSlash);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithColon_shouldReturnValidResult() {
        // Given
        String passwordWithColon = "MyP@ss123:";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithColon);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithSemicolon_shouldReturnValidResult() {
        // Given
        String passwordWithSemicolon = "MyP@ss123;";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithSemicolon);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithComma_shouldReturnValidResult() {
        // Given
        String passwordWithComma = "MyP@ss123,";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithComma);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithPeriod_shouldReturnValidResult() {
        // Given
        String passwordWithPeriod = "MyP@ss123.";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithPeriod);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithLessThan_shouldReturnValidResult() {
        // Given
        String passwordWithLessThan = "MyP@ss123<";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithLessThan);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithGreaterThan_shouldReturnValidResult() {
        // Given
        String passwordWithGreaterThan = "MyP@ss123>";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithGreaterThan);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithTilde_shouldReturnValidResult() {
        // Given
        String passwordWithTilde = "MyP@ss123~";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithTilde);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithCaret_shouldReturnValidResult() {
        // Given
        String passwordWithCaret = "MyP@ss123^";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithCaret);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithBacktick_shouldReturnValidResult() {
        // Given
        String passwordWithBacktick = "MyP@ss123`";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithBacktick);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithQuote_shouldReturnValidResult() {
        // Given
        String passwordWithQuote = "MyP@ss123\"";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithQuote);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void validatePassword_withValidPasswordWithSingleQuote_shouldReturnValidResult() {
        // Given
        String passwordWithSingleQuote = "MyP@ss123'";

        // When
        PasswordValidator.PasswordValidationResult result = passwordValidator.validatePassword(passwordWithSingleQuote);

        // Then
        assertTrue(result.isValid());
        assertTrue(result.getErrors().isEmpty());
    }
} 