package com.pay.payment_system.DTO;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = DomainConstraintValidator.class)
@Target({ ElementType.FIELD, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidDomain {
    String message() default "The email domain does not exist or cannot receive messages.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
