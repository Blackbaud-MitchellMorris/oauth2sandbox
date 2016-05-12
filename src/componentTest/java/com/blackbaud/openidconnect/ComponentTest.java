package com.blackbaud.openidconnect;

import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.web.WebAppConfiguration;

import java.lang.annotation.*;

@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@SpringApplicationConfiguration(classes = {Openidconnect.class, TestConfig.class})
@WebAppConfiguration
@IntegrationTest({"server.port=10000", "management.port=10001"})
public @interface ComponentTest {

}
