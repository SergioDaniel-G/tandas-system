package com.pay.payment_system.DTO;

import jakarta.validation.constraints.Email;
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
    private String name;

    @NotBlank(message = "{user.lastname.required}")
    @Size(max = 100, message = "{user.lastname.toolong}")
    private String lastname;

    @NotBlank(message = "{user.email.required}")
    @Email(regexp = "^[A-Za-z0-9+_.-]+@(.+)$", message = "{validation.email.invalid}")
    private String email;

    @NotBlank(message = "{user.password.required}")
    @Size(min = 8, max = 12, message = "{validation.password.size}")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^a-zA-Z0-9]).{8,12}$",
            message = "{validation.password.complex}"
    )
    @ToString.Exclude
    private String password;

    @NotBlank(message = "{user.phone.required}")
    @Pattern(regexp = "^\\d{10}$", message = "{validation.phone.invalid}")
    private String mobileNumber;


    public void normalizeData() {
        if (this.email != null) {
            this.email = this.email.toLowerCase().trim();
        }
    }
}
