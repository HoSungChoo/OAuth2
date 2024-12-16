package com.spring.oauth2.config;

import com.spring.oauth.oauth.HttpCookieOAuth2AuthorizationRequestRepository;
import com.spring.oauth.oauth.handler.OAuthAuthenticationFailureHandler;
import com.spring.oauth.oauth.handler.OAuthAuthenticationSuccessHandler;
import com.spring.oauth.oauth.service.CustomOAuthUserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);
    private final CustomOAuthUserService customOAuthUserService;
    private final OAuthAuthenticationSuccessHandler oAuthAuthenticationSuccessHandler;
    private final OAuthAuthenticationFailureHandler oAuthAuthenticationFailureHandler;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        log.info("SecurityFilterChain begin");

        http.csrf(AbstractHttpConfigurer::disable)
                // csrf 설정
                .headers(headersConfigurer -> headersConfigurer.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))

                // Form 로그인 방식 비활성화
                .formLogin(AbstractHttpConfigurer::disable)

                // HTTP Basic 로그인 방식 비활성화
                .httpBasic(AbstractHttpConfigurer::disable)

                // Path 접근 권한 설정
                .authorizeHttpRequests((requests)-> requests
                        .requestMatchers(antMatcher("/api/admin/**")).hasRole("ADMIN") // 해당 경로는 ADMIN만 접근 가능
                        .requestMatchers(antMatcher("/api/user/**")).hasRole("USER") // 해당 경로는 USER만 접근 가능
                        .requestMatchers(antMatcher("/h2-console/**")).permitAll() // 해당 경로는 모두 접근 가능
                        .anyRequest().authenticated() // 나머지 경로는 로그인한 사용자만 접근 가능
                )

                // 세션 관리 방식 정의. STATELESS는 세션을 사용하지 않기 때문에, 클라이언트는 각 요청마다 인증 정보를 제공해야 함
                .sessionManagement(sessions
                        -> sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Default 설정
                .oauth2Login(configure ->
                        configure.authorizationEndpoint(config
                                        -> config.authorizationRequestRepository(httpCookieOAuth2AuthorizationRequestRepository))
                                .userInfoEndpoint(config -> config.userService(customOAuthUserService))
                                .successHandler(oAuthAuthenticationSuccessHandler)
                                .failureHandler(oAuthAuthenticationFailureHandler)
                );

        log.info("SecurityFilterChain end");
        return http.build();
    }
}
