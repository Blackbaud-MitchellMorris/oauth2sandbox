package com.blackbaud.openidconnect;

import com.blackbaud.testsupport.BaseTestConfig;
import com.blackbaud.testsupport.TestTokenSupport;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TestConfig extends BaseTestConfig {

    @Autowired
    TestTokenSupport testTokenSupport;

}
