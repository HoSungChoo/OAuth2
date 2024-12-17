package com.spring.oauth2.config;

import com.spring.oauth2.handler.CustomSuccessHandler;
import com.spring.oauth2.jwt.JWTFilter;
import com.spring.oauth2.jwt.JWTUtil;
import com.spring.oauth2.service.CustomOAuth2UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;
    private final JWTUtil jwtUtil;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        System.out.println("SecurityConfig:filterChain exec");
        // cors 설정
        http.cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration configuration = new CorsConfiguration();

                configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT"));
                configuration.setAllowCredentials(true); // Client가 요청에 인증 정보(쿠키, Authorization Header)를 포함할 수 있다.
                configuration.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization"));
                configuration.setMaxAge(3600L);

                // Client가 접근할 수 있는 헤더 설정
                configuration.setExposedHeaders(Arrays.asList("Set-Cookie", "Authorization"));

                return configuration;
            }
        }));
        // csrf 비활성화
        http.csrf(AbstractHttpConfigurer::disable);

        // From 로그인 방식 비활성화
        http.formLogin(AbstractHttpConfigurer::disable);

        // HTTP Basic 인증 방식 비활성화
        http.httpBasic(AbstractHttpConfigurer::disable);

        // JWTFilter 추가. JWTFilter 는 토큰을 검증하며, 사용자 정보를 Spring Security 컨텍스트에 등록한다.
        http.addFilterAfter(new JWTFilter(jwtUtil), OAuth2LoginAuthenticationFilter.class);

        // oauth2
        http.oauth2Login((oauth2) -> oauth2
                .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                        .userService(customOAuth2UserService)) // access token -> userInfo 메서드가 실행을 마칠 경우 발동
                .successHandler(customSuccessHandler)); // userService 내부 메서드가 실행을 마칠 경우 발동

        // 경로별 인가 작업
        http.authorizeHttpRequests((auth)
                -> auth
                .requestMatchers("/").permitAll() // root 접근은 전부 허용
                .anyRequest().authenticated()); // 나머지 접근은 인증된 사용자만 허용

        // 세션 설정 : STATELESS
        // STATELESS는 세션을 사용하지 않기 때문에, 클라이언트는 각 요청마다 인증 정보를 제공해야 함
        http.sessionManagement((session)
                -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
