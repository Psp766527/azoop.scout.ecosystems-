package com.azoop.scout.validation;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class PasswordConstraintValidator implements ConstraintValidator<ValidPassword,String> {
    @Override
    public void initialize(ValidPassword constraintAnnotation) {}

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        /*PasswordValidator validator = new PasswordValidator(
                // At least 8 characters
                new LengthRule(8, 30),

                // At least one upper-case character
                new CharacterRule(EnglishCharacterData.UpperCase, 1),

                // At least one lower-case character
                new CharacterRule(EnglishCharacterData.LowerCase, 1),

                // At least one digit
                new CharacterRule(EnglishCharacterData.Digit, 1),

                // At least one special character
                new CharacterRule(EnglishCharacterData.Special, 1),

                // No whitespace
                new WhitespaceRule()
        );

        RuleResult result = validator.validate(new PasswordData(password));
        if (result.isValid()) {
            return true;
        }

        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(
                String.join(",", validator.getMessages(result))
        ).addConstraintViolation();*/
        return false;
    }
}
