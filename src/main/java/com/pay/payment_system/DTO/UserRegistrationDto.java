package com.pay.payment_system.DTO;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationDto {

    @NotBlank(message = "{user.name.required}")
    @Size(max = 100, message = "{user.name.toolong}")
    @Pattern(regexp = "^[A-Za-zÁéíóúÁÉÍÓÚñÑ\\s]+$", message = "{user.name.invalid}")
    private String name;

    @NotBlank(message = "{user.lastname.required}")
    @Size(max = 100, message = "{user.lastname.toolong}")
    @Pattern(regexp = "^[A-Za-zÁéíóúÁÉÍÓÚñÑ\\s]+$", message = "{user.lastname.invalid}")
    private String lastname;

    @NotBlank(message = "{user.email.required}")
    @Size(max = 254, message = "{validation.email.toolong}")
    @Pattern(
            regexp = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}$",
            message = "{validation.email.invalid}"
    )
    private String email;

    @NotBlank(message = "{user.password.required}")
    @ValidPassword
    @ToString.Exclude
    private String password;

    @NotBlank(message = "{user.phone.required}")
    @Pattern(regexp = "^\\d{10}$", message = "{validation.phone.invalid}")
    private String mobileNumber;

    public void normalizeData() {
        if (this.name != null) this.name = this.name.trim();
        if (this.lastname != null) this.lastname = this.lastname.trim();
        if (this.email != null) this.email = this.email.trim();
        if (this.mobileNumber != null) this.mobileNumber = this.mobileNumber.trim();
    }

    // TRANSFORMS THE EMAIL INTO A CANONICAL FORMAT TO ENSURE SYSTEM UNIQUENESS

    public String getCanonicalEmailForUniqueness() {
        return com.pay.payment_system.DTO.EmailCanonicalizer.canonicalize(this.email);
    }

}