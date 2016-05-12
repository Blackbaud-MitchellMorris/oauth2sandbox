package com.blackbaud.openidconnect.core;

import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import java.time.Clock;

@Component
public class ClockSource {
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
