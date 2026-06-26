package com.pay.payment_system.service;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.DTO.UserRegistrationDto;
import com.pay.payment_system.configservice.LoginLockoutEvaluationService;
import com.pay.payment_system.entity.Role;
import com.pay.payment_system.entity.UserAccount;
import com.pay.payment_system.entity.UserSecurity;
import com.pay.payment_system.repository.RoleRepository;
import com.pay.payment_system.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginLockoutEvaluationService lockoutEvaluationService;

    @Override
    @Transactional
    public UserAccount save(UserRegistrationDto dto) {
        log.info("USER SERVICE: Registering new user account with email: {}", safe (dto.getEmail()));

        Role defaultRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("ROLE_USER could not be found in the database."));

        UserAccount user = UserAccount.builder()
                .name(dto.getName())
                .lastname(dto.getLastname())
                .email(dto.getEmail().trim().toLowerCase())
                .password(passwordEncoder.encode(dto.getPassword()))
                .mobileNumber(dto.getMobileNumber())
                .roles(Set.of(defaultRole))
                .build();

        UserSecurity security = UserSecurity.builder().user(user).build();
        user.setSecurity(security);

        return userRepository.save(user);
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        if (username == null || username.isBlank()) {
            throw new UsernameNotFoundException("Username cannot be null or empty.");
        }
        String formattedEmail = username.trim().toLowerCase();

        if (lockoutEvaluationService.isAccountLocked(formattedEmail, null)) {
            long remainingSeconds = lockoutEvaluationService.getRemainingLockoutTimeInSeconds(formattedEmail);

            throw new org.springframework.security.core.userdetails.UsernameNotFoundException(
                    "Too many failed attempts. Account temporarily frozen. Retry after " + remainingSeconds + " seconds."
            );
        }

        UserAccount user = userRepository.findByEmailWithSecurityAndRoles(formattedEmail)
                .orElseThrow(() -> new UsernameNotFoundException("Invalid username or password."));

        UserSecurity security = user.getSecurity();
        if (security == null) {
            log.error("SECURITY CRITICAL: User {} exists but has no UserSecurity profile linked.", safe (formattedEmail));
            throw new UsernameNotFoundException("Invalid username or password.");
        }

        boolean isLockedInMySQL = !security.isAccountNonLocked();
        if (isLockedInMySQL) {
            log.warn("SECURITY LOCK: User {} is locked permanently in MySQL.", safe (formattedEmail));
            throw new org.springframework.security.authentication.LockedException("Account permanently locked.");
        }

        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            HttpServletRequest request = attributes.getRequest();
            request.setAttribute("LOCKOUT_EMAIL", formattedEmail);
        }

        List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());

        return new User(
                user.getEmail(),
                user.getPassword(),
                true,
                true,
                true,
                true,
                authorities
        );
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserAccount> findAllUsers() {
        log.info("USER SERVICE: Fetching all users.");
        return userRepository.findAll();
    }

    @Override
    @Transactional(readOnly = true)
    public UserAccount findByEmail(String email) {
        if (email == null || email.isBlank()) {
            return null;
        }
        return userRepository.findByEmail(email.trim().toLowerCase());
    }

    @Override
    @Transactional
    public void updateLastLoginDate(String email, LocalDateTime loginDate) {
        if (email == null || email.isBlank()) return;

        UserAccount user = userRepository.findByEmail(email.trim().toLowerCase());
        if (user != null && user.getSecurity() != null) {
            user.getSecurity().setLastLogin(loginDate);

            userRepository.save(user);
        }
    }
}