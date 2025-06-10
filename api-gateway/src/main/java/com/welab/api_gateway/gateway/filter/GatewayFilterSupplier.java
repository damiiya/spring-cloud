package com.welab.api_gateway.gateway.filter;

import org.springframework.cloud.gateway.server.mvc.filter.SimpleFilterSupplier;
import org.springframework.context.annotation.Configuration;

/*
* <GatewayFilterFunctions를 Spring Cloud Gateway MVC에 공급자(Supplier)로 등록하는 구성 클래스>
* SimpleFilterSupplier는 HandlerFilterFunction을 스캔하여 Gateway에 자동 등록
* */
@Configuration
public class GatewayFilterSupplier extends SimpleFilterSupplier {
    public GatewayFilterSupplier() {
        super(GatewayFilterFunctions.class);
    }
}
