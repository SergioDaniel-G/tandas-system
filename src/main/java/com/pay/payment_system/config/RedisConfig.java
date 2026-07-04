package com.pay.payment_system.config;

import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.codec.RedisCodec;
import io.lettuce.core.codec.StringCodec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RedisConfig {

    @Value("${spring.data.redis.host}")
    private String redisHost;

    @Value("${spring.data.redis.port}")
    private int redisPort;

    // INITIALIZES THE REDIS CLIENT WITH SYSTEM CONFIGURATION HOST AND PORT FOR CENTRALIZED STORAGE

    @Bean(destroyMethod = "shutdown")
    public RedisClient redisClient() {
        return RedisClient.create(RedisURI.create(redisHost, redisPort));
    }

    // ESTABLISHES A STATEFUL REDIS CONNECTION UTILIZING UTF-8 STRING KEYS AND BYTE ARRAY VALUES

    @Bean(destroyMethod = "close")
    public StatefulRedisConnection<String, byte[]> statefulRedisConnection(RedisClient redisClient) {
        return redisClient.connect(RedisCodec.of(StringCodec.UTF8, ByteArrayCodec.INSTANCE));
    }

    // CONFIGURES THE PROXY MANAGER BASED ON THE LETTUCE DRIVER TO DISTRIBUTE RATE LIMITING TOKENS VIA REDIS

    @Bean
    public ProxyManager<String> proxyManager(StatefulRedisConnection<String, byte[]> redisConnection) {
        return LettuceBasedProxyManager.builderFor(redisConnection).build();
    }
}