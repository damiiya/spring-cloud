package com.welab.api_gateway.security.filter;

import com.welab.api_gateway.security.jwt.JwtTokenValidator;
import com.welab.api_gateway.security.jwt.authentification.JwtAuthentication;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/*
* <Spring Security에서 JWT 기반 인증을 처리하는 필터>
* 요청이 들어올 때마다 한 번 실행되며, JWT 토큰을 검증하고 SecurityContext에 인증 객체를 등록하는 역할
* 이 필터가 없다면 JWT 기반 인증을 할 수 없음
* Spring Security는 기본적으로 세션 기반 인증을 사용하므로, JWT를 사용하려면 이처럼 직접 필터를 구현해야 함
*  */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenValidator jwtTokenValidator;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String jwtToken = jwtTokenValidator.getToken(request);

        if (jwtToken != null) {
            JwtAuthentication authentication = jwtTokenValidator.validateToken(jwtToken);
            if (authentication != null) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }
}