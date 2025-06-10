package com.welab.api_gateway.config;

import com.welab.api_gateway.security.filter.JwtAuthenticationFilter;
import com.welab.api_gateway.security.jwt.JwtTokenValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/*
* <Spring Security의 핵심 설정 클래스>
* JWT 기반 인증, 세션 비활성화, CORS, 인증 URL 허용 범위 등을 정의
* */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final JwtTokenValidator jwtTokenValidator;

    /*
    * <주요 보안 설정을 담고 있는 메서드>
    * CORS 설정 - corsConfigurationSource()
    * CSRF 보호 - 비활성화(JWT 기반 인증에서는 서버가 상태를 유지하지 않기 때문에 CSRF 공격에 덜 취약)
    * securityMatcher - 모든 요청 URL에 대해 이 보안 설정을 적용
    *   ** Spring Security 6부터는 securityMatcher()로 URL 패턴을 지정
    * 세션 설정 - 비활성화(JWT 기반 인증에서는 세션을 사용하지 않으므로 stateless로 설정)
    * 폼 로그인, HTTP Basic 인증 - 비활성화(둘 다 사용하지 않으며, 대신 JWT로 인증을 처리)
    * JWT 인증 필터 등록 - 인증 요청 시 JWT를 검증하는 JwtAuthenticationFilter를 기본 인증 필터 전에 실행되도록 설정
    * 인가 설정 - /api/user/v1/auth/** 경로는 인증 없이 접근 허용(그 외 모든 요청은 인증 필요)
    * */
    @Bean
    public SecurityFilterChain applicationSecurity(HttpSecurity http) throws Exception {
        http.cors(httpSecurityCorsConfigurer -> {
                    httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource());
                })
                .csrf(AbstractHttpConfigurer::disable)
                .securityMatcher("/**") // map current config to given resource path
                .sessionManagement(sessionManagementConfigurer
                        -> sessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .addFilterBefore(
                        new JwtAuthenticationFilter(jwtTokenValidator),
                        UsernamePasswordAuthenticationFilter.class
                )
                .authorizeHttpRequests(registry -> registry
                        .requestMatchers("/api/user/v1/auth/**").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    /*
    * <CORS 설정>
    * 모든 Origin(*) 허용
    * 모든 HTTP 메서드, 헤더 허용
    * 인증 정보를 포함한 요청도 허용 (AllowCredentials = true)
    * 모든 응답 헤더 노출 허용
    * */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true);
        // config.setAllowedOrigins(List.of("*"));
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("*"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }
}