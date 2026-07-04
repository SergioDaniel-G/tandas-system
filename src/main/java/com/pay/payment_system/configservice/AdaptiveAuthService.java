package com.pay.payment_system.configservice;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.entity.UserSecurity;
import com.pay.payment_system.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdaptiveAuthService {

    private final UserRepository userRepository;
    private final IpService ipService;
    private final MfaEmailService mfaEmailService;
    private final UserSecurityService userSecurityService;
    private final StringRedisTemplate redisTemplate;

    private final HttpSessionSecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();

    // EVALUATES SECURITY RISKS AND TRIGGERS INTERMEDIATE MFA CHALLENGES ACCORDING TO DEVICE AND IP REPUTATION

    @Transactional
    public String processAdaptiveLogin(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication,
                                       UserAccount userAccount,
                                       UserSecurity security) {

        String email = authentication.getName();
        String cleanEmail = email.trim().toLowerCase();

        String lockKey = "login:lock:" + cleanEmail;
        if (Boolean.TRUE.equals(redisTemplate.hasKey(lockKey))) {
            log.warn("ADAPTIVE LOGIN BLOCKED: User {} tried to login, but has an active progressive RAM lock.", safe (email));
            return "REDIRECT_BLOCKED";
        }

        String ip = request.getRemoteAddr();
        boolean isKnownDevice = ipService.isIpKnown(userAccount, ip);

        if (isKnownDevice) {
            log.info("ADAPTIVE AUTH: KNOWN IP DETECTED ({}) FOR USER {}. BYPASSING MFA.",safe (ip), safe (email));

            security.updateLastLogin();
            security.resetFailedAttempts();

            var realAuthorities = userAccount.getRoles().stream()
                    .map(role -> new SimpleGrantedAuthority(role.getName()))
                    .toList();

            Authentication fullAuth = new UsernamePasswordAuthenticationToken(
                    authentication.getPrincipal(),
                    null,
                    realAuthorities
            );

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(fullAuth);
            SecurityContextHolder.setContext(context);

            securityContextRepository.saveContext(context, request, response);

            ipService.registerAccessAttempt(userAccount, "SUCCESSFUL", "Automatic access via known IP", request);
            return "KNOWN_DEVICE";

        } else {

            log.warn("ADAPTIVE AUTH: UNKNOWN OR NEW IP DETECTED ({}) FOR USER {}. INITIATING MFA CHALLENGE.",safe (ip), safe (email));

            ipService.registerAccessAttempt(userAccount, "INITIAL_LOGIN", "Step 1: Correct credentials", request);

            String cryptoToken = userSecurityService.generateAndSendOtp(userAccount.getId(), email);

            var session = request.getSession(true);
            session.setAttribute("OTP_CRYPTO_TOKEN", cryptoToken);

            Authentication partialAuth = new UsernamePasswordAuthenticationToken(
                    authentication.getPrincipal(),
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_PRE_VERIFIED"))
            );

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(partialAuth);
            SecurityContextHolder.setContext(context);

            securityContextRepository.saveContext(context, request, response);

            return "UNKNOWN_DEVICE";
        }
    }
}