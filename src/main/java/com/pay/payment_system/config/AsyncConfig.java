package com.pay.payment_system.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

@Configuration
@EnableAsync
public class AsyncConfig {

    // CONFIGURES A CUSTOM THREAD POOL EXECUTOR TO MANAGE ASYNCHRONOUS EMAIL AND MFA TRANSMISSIONS

    @Bean(name = "mailTaskExecutor")
    public Executor mailTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        // DEFINES CONCURRENCY LIMITS, QUEUE CAPACITY, AND RETRY POLICIES FOR THE ASYNCHRONOUS POOL

        executor.setCorePoolSize(15);
        executor.setMaxPoolSize(50);
        executor.setQueueCapacity(500);
        executor.setThreadNamePrefix("MfaMailThread-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());

        // ENSURES GRACEFUL SHUTDOWN BEHAVIOR TO PREVENT DATA LOSS WHEN THE APPLICATION TERMINATES

        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        executor.initialize();
        return executor;
    }
}