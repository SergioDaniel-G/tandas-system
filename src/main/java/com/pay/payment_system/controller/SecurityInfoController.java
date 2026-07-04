package com.pay.payment_system.controller;

import com.pay.payment_system.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class SecurityInfoController {

    private final UserService userService;

    // EVALUATES ACTIVE AUTHENTICATION PRINCIPALS TO DETERMINE IF ADMIN SYSTEM PRIVILEGES ARE GRANTED

    @GetMapping("/api/users/is-admin")
    @ResponseBody
    public ResponseEntity<Boolean> checkIfAdmin(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            boolean isAdmin = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .anyMatch(role -> role.equals("ROLE_ADMIN") || role.equals("ADMIN"));

            return ResponseEntity.ok(isAdmin);
        }
        return ResponseEntity.ok(false);
    }
}