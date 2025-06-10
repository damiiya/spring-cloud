package com.welab.api_gateway.common.util;

import jakarta.servlet.http.HttpServletRequest;

/*
* <클라이언트 IP 주소를 추출하는 유틸리티 클래스>
*
*
*
* */
public class HttpUtils {
    public static String getRemoteAddr(HttpServletRequest request) {
        String remoteAddr = request.getHeader("X-FORWARDED-FOR");
        if (remoteAddr == null) {
            remoteAddr = request.getRemoteAddr();
        }

        String[] pair = remoteAddr.split(":");
        if (pair.length > 0) {
            return pair[0];
        } else {
            return "";
        }

    }
}
