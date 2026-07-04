package com.pay.payment_system.DTO;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

/* CUSTOM ANNOTATION TO VALIDATE USER PASSWORDS
 * ENFORCES SECURITY COMPLIANCE BY LINKING TO A CUSTOM VALIDATOR
 */

@Documented
@Constraint(validatedBy = PasswordConstraintValidator.class)
@Target({ ElementType.FIELD, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPassword {
    String message() default "The password does not meet security requirements or is too common.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
