package com.pay.payment_system.components;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.configservice.AdaptiveAuthService;
import com.pay.payment_system.configservice.LoginLockoutEvaluationService;
import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.entity.UserSecurity;
import com.pay.payment_system.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import java.io.IOException;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final AdaptiveAuthService adaptiveAuthService;
    private final LoginLockoutEvaluationService lockoutEvaluationService;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        String email =  authentication.getName();
        UserAccount userAccount = userRepository.findByEmail(email);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        if (userAccount == null) {
            log.error("AUTHENTICATION SUCCESS HANDLER ERROR: USER NOT FOUND FOR EMAIL: {}", safe (email));
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().print("{\"status\":\"ERROR\",\"message\":\"User not found\"}");
            return;
        }

        UserSecurity security = userAccount.getSecurity();

        if (security == null) {
            log.error("SECURITY ENTITY NOT FOUND FOR USER: {}", safe (email));
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().print("{\"status\":\"ERROR\",\"message\":\"Security profile not found\"}");
            return;
        }

        boolean isCurrentlyLocked = lockoutEvaluationService.isAccountLocked(email,null);

        if (isCurrentlyLocked && (security.isBlocked() || !security.isAccountNonLocked())) {
            log.warn("BLOCKED LOGIN ATTEMPT FOR USER: {}", safe (email));

            long remainingSeconds = lockoutEvaluationService.getRemainingLockoutTimeInSeconds(email);

            response.setStatus(HttpStatus.LOCKED.value());
            response.getWriter().print(String.format("""
                {
                  "status": "BLOCKED",
                  "message": "Your account has been locked due to multiple failed login attempts.",
                  "retryAfterSeconds": %d
                }
                """, remainingSeconds));
            return;
        }

        security.unlockAccount();

        userRepository.saveAndFlush(userAccount);

        lockoutEvaluationService.resetAttempts(email);

        log.info("LOGIN SUCCESS: Counter reset and database flushed to 0 for user: {}", safe (email));

        String authResult = adaptiveAuthService.processAdaptiveLogin(request, response, authentication, userAccount, security);

        if ("KNOWN_DEVICE".equals(authResult)) {
            clearAuthenticationAttributes(request);
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().print("""
                {"status":"SUCCESS","redirect":"/index"}
                """);
        } else {
            request.changeSessionId();

            Authentication preVerifiedAuth = new UsernamePasswordAuthenticationToken(
                    authentication.getPrincipal(),
                    authentication.getCredentials(),
                    List.of(new SimpleGrantedAuthority("ROLE_PRE_VERIFIED"))
            );

            SecurityContextHolder.getContext().setAuthentication(preVerifiedAuth);
            securityContextRepository.saveContext(SecurityContextHolder.getContext(), request, response);

            log.info("MFA required for user {}. Role temporarily downgraded to ROLE_PRE_VERIFIED.", safe (email));

            clearAuthenticationAttributes(request);
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().print("""
                {"status":"MFA_REQUIRED","redirect":"/verify-code"}
                """);
        }
    }
}