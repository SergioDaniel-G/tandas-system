package com.pay.payment_system.configservice;

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
    private final BucketConfiguration bucketConfiguration;

    public RateLimiterService(
            ProxyManager<String> proxyManager,
            @Value("${app.security.rate-limit.capacity}") int capacity,
            @Value("${app.security.rate-limit.refill-tokens}") int refillTokens) {

        this.proxyManager = proxyManager;

        this.bucketConfiguration = BucketConfiguration.builder()
                .addLimit(Bandwidth.classic(capacity, Refill.greedy(refillTokens, Duration.ofMinutes(1))))
                .build();

        log.info("MEMURAI Rate Limiting Bucket configured successfully. Capacity: {}, Refill: tokens every min.", capacity, refillTokens);
    }

    public boolean tryConsume(String clientIp) {

        String cleanIp = clientIp.replace(":", "-");
        String redisKey = "rate:limit:" + cleanIp;

        try {

            Bucket bucket = proxyManager.builder().build(redisKey, bucketConfiguration);

            boolean canConsume = bucket.tryConsume(1);

            return canConsume;

        } catch (Exception e) {
            log.error(" CRITICAL_ERROR: Failed connect with Redis: ", e);

            return true;
        }
    }
}