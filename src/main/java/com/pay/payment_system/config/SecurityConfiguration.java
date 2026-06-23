package com.pay.payment_system.config;

import com.pay.payment_system.components.CustomLoginFailureHandler;
import com.pay.payment_system.components.CustomLoginSuccessHandler;
import com.pay.payment_system.components.RateLimitingFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final UserDetailsService userService;
    private final PasswordEncoder passwordEncoder;
    private final Environment env;
    private final CustomLoginSuccessHandler customLoginSuccessHandler;
    private final CustomLoginFailureHandler customLoginFailureHandler;
    private final RateLimitingFilter rateLimitingFilter;
    private final CorsConfigurationSource corsConfigurationSource;

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider auth = new DaoAuthenticationProvider();
        auth.setUserDetailsService(userService);
        auth.setPasswordEncoder(passwordEncoder);
        auth.setHideUserNotFoundExceptions(true);
        return auth;
    }

    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
    }

    @Bean
    public org.springframework.security.authentication.AuthenticationManager authenticationManager(ApplicationEventPublisher publisher) {
        ProviderManager providerManager = new ProviderManager(authenticationProvider());
        providerManager.setAuthenticationEventPublisher(new DefaultAuthenticationEventPublisher(publisher));
        return providerManager;
    }

    @Bean
    public FilterRegistrationBean<RateLimitingFilter> registration(RateLimitingFilter filter) {
        FilterRegistrationBean<RateLimitingFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, org.springframework.security.authentication.AuthenticationManager authManager) throws Exception {

        boolean isDev = Arrays.asList(env.getActiveProfiles()).contains("dev");

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .csrf(csrf -> csrf.disable())
                .authenticationManager(authManager)
                .authorizeHttpRequests(authorize -> authorize

                        .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/css/**", "/js/**", "/img/**").permitAll()
                        .requestMatchers("/login", "/login.html", "/register", "/register.html", "/error").permitAll()
                        .requestMatchers("/forgot_password.html", "/reset_password.html").permitAll()
                        .requestMatchers("/api/users/register", "/api/users/recaptcha-key", "/api/register", "/api/config/**").permitAll()
                        .requestMatchers("/api/cron/**").permitAll()
                        .requestMatchers("/loadForgotPassword", "/loadForgotPassword/**", "/forgotPassword").permitAll()
                        .requestMatchers("/loadResetPassword/**", "/changePassword/**").permitAll()

                        .requestMatchers("/api/payments/**").authenticated()
                        .requestMatchers("/api/users/is-admin").authenticated()
                        .requestMatchers("/api/users/list").hasRole("ADMIN")

                        .requestMatchers("/verify-code", "/mfa-page.html", "/auth/validate-otp").hasRole("PRE_VERIFIED")
                        .anyRequest().authenticated()
                )

                .exceptionHandling(exception -> exception

                        .authenticationEntryPoint((request, response, ex) -> {
                            response.setStatus(401);
                            response.setContentType("application/json");
                            response.getWriter().write("{\"error\":\"UNAUTHORIZED\"}");
                        })

                        .defaultAuthenticationEntryPointFor(
                                (request, response, authException) -> {
                                    response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED);
                                    response.setContentType("application/json");
                                    response.getWriter().write("{\"status\":\"UNAUTHORIZED\",\"message\":\"Tu sesión intermedia de MFA no existe o expiró. Por favor vuelve a loguearte.\"}");
                                },
                                new AntPathRequestMatcher("/auth/**")
                        )

                        .defaultAuthenticationEntryPointFor(
                                (request, response, ex) -> {
                                    response.setStatus(401);
                                    response.setContentType("application/json");
                                    response.getWriter().write("{\"error\":\"UNAUTHORIZED\"}");
                                },
                                new AntPathRequestMatcher("/api/**")
                        )

                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            String uri = request.getRequestURI();

                            if (uri.startsWith("/api/") || uri.startsWith("/users/")) {
                                response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN);
                                response.setContentType("application/json");
                                response.setCharacterEncoding("UTF-8");
                                response.getWriter().write("{\"error\":\"FORBIDDEN\",\"message\":\"You are not authorized to perform this action.\"}");
                            } else {
                                response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN);
                                request.setAttribute("jakarta.servlet.error.status_code", 403);
                                request.getRequestDispatcher("/error").forward(request, response);
                            }
                        })
                )

                .formLogin(form -> form
                        .loginPage("/login.html")
                        .loginProcessingUrl("/login")
                        .usernameParameter("email")
                        .passwordParameter("password")
                        .successHandler(customLoginSuccessHandler)
                        .failureHandler(customLoginFailureHandler)
                        .permitAll()
                )

                .sessionManagement(session -> session
                        .sessionFixation().migrateSession()
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                )

                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "POST"))
                        .deleteCookies("JSESSIONID")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_OK);
                        })
                        .permitAll()
                );

        if (!isDev) {
            http.requiresChannel(channel -> channel
                    .anyRequest().requiresSecure()
            );
        }

        http.headers(headers -> {
            headers.cacheControl(cache -> cache.disable());

            headers.addHeaderWriter(new org.springframework.security.web.header.writers.StaticHeadersWriter(
                    "Cache-Control", "no-cache, no-store, must-revalidate, max-age=0, private"));
            headers.addHeaderWriter(new org.springframework.security.web.header.writers.StaticHeadersWriter(
                    "Pragma", "no-cache"));
            headers.addHeaderWriter(new org.springframework.security.web.header.writers.StaticHeadersWriter(
                    "Expires", "0"));

            headers.frameOptions(frame -> frame.sameOrigin());
            headers.xssProtection(xss -> xss.headerValue(
                    org.springframework.security.web.header.writers.XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK
            ));

            if (!isDev) {
                headers.contentSecurityPolicy(csp -> csp
                        .policyDirectives("default-src 'self'; " +
                                "script-src 'self' 'unsafe-inline' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; " +
                                "frame-src 'self' https://www.google.com/recaptcha/ https://recaptcha.google.com/; " +
                                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com/ https://cdnjs.cloudflare.com/; " +
                                "font-src 'self' https://fonts.gstatic.com/ https://cdnjs.cloudflare.com/; " +
                                "connect-src 'self'; " +
                                "img-src 'self' data:; " +
                                "upgrade-insecure-requests;")
                );
            }

            headers.httpStrictTransportSecurity(hsts -> {
                if (!isDev) {
                    hsts.includeSubDomains(true)
                            .maxAgeInSeconds(31536000)
                            .preload(true);
                } else {
                    hsts.disable();
                }
            });
        });

        http.addFilterBefore(rateLimitingFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}