package com.pay.payment_system.configservice;

import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.entity.UserSecurity;
import com.pay.payment_system.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    private final HttpSessionSecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();

    @Transactional
    public String processAdaptiveLogin(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication,
                                       UserAccount userAccount,
                                       UserSecurity security) {

        String email = authentication.getName();
        String ip = request.getRemoteAddr();

        boolean isKnownDevice = ipService.isIpKnown(email, ip);

        /*
         * KNOWN DISPOSITIVE → AVOID MFA (BYPASS)
         */
        if (isKnownDevice) {

            log.info("ADAPTIVE AUTH: KNOWN IP DETECTED ({}) FOR USER {}. BYPASSING MFA.", ip, email);

            security.updateLastLogin();
            security.resetFailedAttempts();
            security.setOtpFailedAttempts(0);

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

            ipService.registerAccessAttempt(
                    email,
                    "SUCCESSFUL",
                    "Automatic access via known IP",
                    request
            );

            return "KNOWN_DEVICE";

        } else {
            /*
             * UNKNOWN DISPOSITIVE → REQUIRE MFA
             */
            log.warn("ADAPTIVE AUTH: UNKNOWN OR NEW IP DETECTED ({}) FOR USER {}. INITIATING MFA CHALLENGE.", ip, email);

            ipService.registerAccessAttempt(email, "INITIAL_LOGIN", "Step 1: Correct credentials", request);

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