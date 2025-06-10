package com.welab.api_gateway.gateway.filter;

import org.springframework.cloud.gateway.server.mvc.common.Shortcut;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.ServerResponse;

import static org.springframework.web.servlet.function.HandlerFilterFunction.ofRequestProcessor;

/*
* <Gateway MVC에서 사용할 필터 함수의 정의 집합>
* addAuthenticationHeader()는 정의한 필터를 래핑하여 HandlerFilterFunction 형태로 제공
* @Shortcut: Spring Cloud Gateway MVC의 간편 라우팅 DSL에서 이 함수를 쉽게 호출 가능
* */
public interface GatewayFilterFunctions {
    @Shortcut
    static HandlerFilterFunction<ServerResponse, ServerResponse> addAuthenticationHeader() {
        return ofRequestProcessor(AuthenticationHeaderFilterFunction.addHeader());
    }
}
