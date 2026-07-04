package com.pay.payment_system.configservice;

import static com.pay.payment_system.config.LogSanitizer.safe;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.Refill;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.Duration;

@Slf4j
@Service
public class RateLimiterService {

    private final ProxyManager<String> proxyManager;
    private final BucketConfiguration loginConfiguration;
    private final BucketConfiguration registerConfiguration;
    private final BucketConfiguration defaultConfiguration;

    // CONSTRUCTS DISTRIBUTED RATE LIMITER CONFIGURATIONS ASSIGNING CUSTOM BANDWIDTH RULES FOR LOGIN REGISTER AND DEFAULT ENDPOINTS

    public RateLimiterService(
            ProxyManager<String> proxyManager,
            @Value("${app.security.rate-limit.capacity}") int loginCapacity,
            @Value("${app.security.rate-limit.refill-tokens}") int loginRefillTokens) {

        this.proxyManager = proxyManager;


        this.loginConfiguration = BucketConfiguration.builder()
                .addLimit(Bandwidth.classic(loginCapacity, Refill.greedy(loginRefillTokens, Duration.ofMinutes(1))))
                .build();

        this.registerConfiguration = BucketConfiguration.builder()
                .addLimit(Bandwidth.classic(3, Refill.greedy(1, Duration.ofMinutes(1))))
                .build();

        this.defaultConfiguration = BucketConfiguration.builder()
                .addLimit(Bandwidth.classic(6, Refill.greedy(6, Duration.ofSeconds(1))))
                .build();

        log.info("MEMURAI Rate Limiter initialized: Login Capacity = {}, Register Capacity = 1", loginCapacity);
    }

    // EVALUATES REQUISITIONS AGAINST CLIENT IP AND URI MATCHES TO CONSUME TOKENS VIA DISTRIBUTED REDIS BUCKETS

    public boolean tryConsume(String clientIp, String requestUri) {
        String cleanIp = clientIp.replace(":", "-");
        String lowerUri = requestUri.toLowerCase();

        BucketConfiguration selectedConfig;
        String endpointKey;

        if (lowerUri.contains("login")) {
            selectedConfig = loginConfiguration;
            endpointKey = ":login";
        } else if (lowerUri.contains("register")) {
            selectedConfig = registerConfiguration;
            endpointKey = ":register";
        } else {
            selectedConfig = defaultConfiguration;
            endpointKey = ":default";
        }

        String redisKey = "rate:limit:" + cleanIp + endpointKey;

        try {
            Bucket bucket = proxyManager.builder().build(redisKey, selectedConfig);
            return bucket.tryConsume(1);
        } catch (Exception e) {
            log.error(" CRITICAL_ERROR: Failed to connect with Redis/Memurai: {}", safe(e.getMessage()));
            return true;
        }
    }
}