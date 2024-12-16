package com.spring.oauth2.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CORSMvcConfig implements WebMvcConfigurer {
    //
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // 애플리케이션의 모든 경로에 CORS 적용
                .exposedHeaders("Set-Cookie") // 서버 측에서 노출 가능한 헤더 목록 적용
                .allowedOrigins("http://localhost:3000"); // 해당 경로에서 오는 요청만 허용
    }
}
