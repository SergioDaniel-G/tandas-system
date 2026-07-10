package com.pay.payment_system.configservice;

import com.pay.payment_system.entity.UserAccount;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class MfaSecurityContextService {

    private final SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();

    // UPGRADES PRE-AUTHENTICATED MFA TOKENS TO FULLY AUTHORIZED SECURITY CONTEXTS MAPPING ACTUAL DATABASE SYSTEM ROLES

    public void upgradeToFullAuthentication(Authentication auth, UserAccount userAccount, HttpServletRequest request, HttpServletResponse response) {

        var realAuthorities = userAccount.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());

        Authentication newAuth = new UsernamePasswordAuthenticationToken(
                auth.getPrincipal(),
                null,
                realAuthorities
        );

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(newAuth);

        SecurityContextHolder.setContext(context);

        securityContextRepository.saveContext(context, request, response);
    }
}