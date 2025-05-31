package org.example.oauthjwt.Config;

import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {
    // WebMvcConfigurer 인터페이스는 Spring MVC의 설정을 커스터마이징할 수 있는 메소드를 제공합니다.
    // 이 인터페이스를 구현함으로써, 개발자는 Spring MVC의 기본 설정을 변경하거나 추가할 수 있습니다.
    // 예를 들어, CORS 설정, 뷰 리졸버, 메시지 컨버터 등을 정의할 수 있습니다.
    // addCorsMappings 메소드를 오버라이드하여 CORS 설정을 추가할 수 있습니다.

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .exposedHeaders("Set-Cookie")
                .allowedOrigins("http://localhost:3000"); // React app URL
    }
}
