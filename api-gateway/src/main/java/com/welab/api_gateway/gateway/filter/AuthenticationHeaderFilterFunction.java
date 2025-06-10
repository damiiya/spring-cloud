package com.welab.api_gateway.gateway.filter;

import com.welab.api_gateway.common.util.HttpUtils;
import com.welab.api_gateway.security.jwt.authentification.UserPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.function.ServerRequest;

import java.util.function.Function;

/*
* <HTTP 요청을 가로채서 인증/식별 관련 헤더를 추가하는 필터 함수>
* - X-Auth-UserId: 인증된 사용자 ID
* - X-Client-Address: 클라이언트 IP 주소
* - X-Client-Device: 디바이스 정보 (현재는 “WEB” 고정)
* SecurityContextHolder를 통해 인증 객체에서 사용자 정보를 가져옴
* UserPrincipal 타입일 때만 userId를 추출해 헤더로 설정
* */
class AuthenticationHeaderFilterFunction {
    public static Function<ServerRequest, ServerRequest> addHeader() {
        return request -> {
            ServerRequest.Builder requestBuilder = ServerRequest.from(request);

            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            if (principal instanceof UserPrincipal userPrincipal) {
                requestBuilder.header("X-Auth-UserId", userPrincipal.getUserId());

                // 필요시 권한 입력 정보
                // requestBuilder.header("X-Auth-Authorities", ...);
            }

            String remoteAddr = HttpUtils.getRemoteAddr(request.servletRequest());
            requestBuilder.header("X-Client-Address", remoteAddr);

            // org.springframework.boo:spring-boot-starter-mobile:1.5.22.RELEASE

            String device = "WEB";
            requestBuilder.header("X-Client-Device", device);


            return requestBuilder.build();
        };
    }
}
