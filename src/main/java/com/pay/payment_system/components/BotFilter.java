package com.pay.payment_system.components;

import static com.pay.payment_system.config.LogSanitizer.safe;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class BotFilter implements Filter {

    private final RequestDeviceParser requestDeviceParser;

    private final Map<String, Bucket> logThrottlingBuckets = new ConcurrentHashMap<>();

    private final Map<String, AtomicLong> blockedAttemptsCounter = new ConcurrentHashMap<>();

    public BotFilter(RequestDeviceParser requestDeviceParser) {
        this.requestDeviceParser = requestDeviceParser;
    }

    //INTERCEPTS AND PROCESSES EVERY INCOMING HTTP REQUEST TO THE SERVER

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if ("/login".equals(httpRequest.getRequestURI()) && "POST".equalsIgnoreCase(httpRequest.getMethod())) {
            String userAgent = httpRequest.getHeader("User-Agent");

            if (requestDeviceParser.detectBot(userAgent)) {
                String clientIp = httpRequest.getRemoteAddr();

                if (tryConsumeLogToken(clientIp)) {

                    long accumulated = blockedAttemptsCounter.computeIfAbsent(clientIp, k -> new AtomicLong(0)).getAndSet(0);

                    if (accumulated > 0) {
                        log.warn("SECURITY ALERT: Automated tool '{}' blocked from IP {}. [Plus {} silent requests blocked in the last interval]",
                                safe(userAgent), safe(clientIp), accumulated);
                    } else {
                        log.warn("SECURITY ALERT [IMMEDIATE]: Automated tool '{}' blocked from accessing /login from IP {}",
                                safe(userAgent), safe(clientIp));
                    }
                } else {

                    blockedAttemptsCounter.computeIfAbsent(clientIp, k -> new AtomicLong(0)).incrementAndGet();
                }

                httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
                httpResponse.setContentType("application/json");
                httpResponse.setCharacterEncoding("UTF-8");
                httpResponse.getWriter().print("""
                        {
                          "status": "BOT_DETECTED",
                          "message": "Automated requests are not allowed on this endpoint."
                        }
                        """);
                httpResponse.getWriter().flush();
                return;
            }
        }

        chain.doFilter(request, response);
    }

    //CONTROLS AND LIMITS THE FREQUENCY OF IP LOCKOUT LOG WRITING

    private boolean tryConsumeLogToken(String ip) {
        return logThrottlingBuckets.computeIfAbsent(ip, key ->
                Bucket.builder()
                        .addLimit(Bandwidth.classic(2, Refill.intervally(1, Duration.ofSeconds(15))))
                        .build()
        ).tryConsume(1);
    }
}