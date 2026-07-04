package com.pay.payment_system.components;

import static com.pay.payment_system.config.LogSanitizer.safe;
import com.pay.payment_system.configservice.RateLimiterService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimitingFilter extends OncePerRequestFilter {

    private final RateLimiterService rateLimiterService;

    // EXTRACTS THE CLIENT IP ADDRESS, CHECKING THE X-FORWARDED-FOR HEADER TO HANDLE PROXIES OR LOAD BALANCERS

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty()) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }

    // INTERCEPTS AND EVALUATES EVERY HTTP REQUEST ONCE TO APPLY RATE LIMITING CONTROLS ON SENSITIVE ENDPOINTS

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestUri = request.getRequestURI();
        String method = request.getMethod();


        if ("OPTIONS".equalsIgnoreCase(method)) {
            filterChain.doFilter(request, response);
            return;
        }

        String lowerUri = requestUri.toLowerCase();

        boolean isTargetEndpoint =

                (requestUri.toLowerCase().contains("login") && "POST".equalsIgnoreCase(method))

                        || (requestUri.toLowerCase().contains("register") && "POST".equalsIgnoreCase(method))

                        || (requestUri.toLowerCase().contains("forgotpassword") && "POST".equalsIgnoreCase(method))
                        || (requestUri.toLowerCase().contains("asyncconfigtest"));

        if (isTargetEndpoint) {
            String clientIp = getClientIp(request);

            // EVALUATES IF THE IP ADDRESS HAS SUFFICIENT TOKENS TO PROCEED WITH THE REQUEST ON THE TARGET URI

            boolean canConsume = rateLimiterService.tryConsume(clientIp, requestUri);

            if (!canConsume) {
                log.warn("BLOCKED FOR RATELIMIT IP: {} on URI: {}", safe(clientIp), safe(requestUri));

                // CONFIGURES CORS HEADERS DYNAMICALLY FOR REJECTED REQUESTS ORIGINATING FROM LOCAL DEVELOPMENT ENVIRONMENTS

                String origin = request.getHeader("Origin");
                if (origin != null && (origin.contains("localhost:5500") || origin.contains("127.0.0.1:5500"))) {
                    response.setHeader("Access-Control-Allow-Origin", origin);
                    response.setHeader("Access-Control-Allow-Credentials", "true");
                }

                // REJECTS THE REQUEST WITH A HTTP 429 TOO MANY REQUESTS STATUS AND A JSON ERROR RESPONSE

                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.getWriter().write("{\"error\": \"Too many requests. Please try again later.\"}");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}