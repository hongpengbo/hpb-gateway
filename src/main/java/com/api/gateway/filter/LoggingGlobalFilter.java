package com.api.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;

/**
 * 全局日志过滤器，记录所有经过网关的请求信息
 *
 * @author api
 * @date 2026/04/10
 */
@Slf4j
@Component
public class LoggingGlobalFilter implements GlobalFilter, Ordered {

    /**
     * 无法获取远程地址时的默认值
     */
    private static final String UNKNOWN_ADDRESS = "unknown";

    /**
     * 无法获取 traceId 时的默认值
     */
    private static final String TRACE_ID_NOT_AVAILABLE = "N/A";

    /**
     * 状态码获取失败时的默认值
     */
    private static final int DEFAULT_STATUS_CODE = 0;

    /**
     * 过滤器顺序：在 TraceId 过滤器之后执行
     */
    public static final int ORDER = TraceIdGlobalFilter.ORDER + 1;

    /**
     * 记录请求和响应日志，包含请求方法、路径、来源 IP、响应状态码和耗时
     *
     * @param exchange 当前请求上下文
     * @param chain    过滤器链
     * @return 响应完成信号
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        HttpMethod httpMethod = request.getMethod();
        String method = httpMethod != null ? httpMethod.name() : UNKNOWN_ADDRESS;
        String remoteAddress = resolveRemoteAddress(request);

        String traceId = exchange.getAttribute(TraceIdGlobalFilter.TRACE_ID_MDC_KEY);
        if (traceId == null) {
            traceId = TRACE_ID_NOT_AVAILABLE;
        }

        long startTime = System.currentTimeMillis();
        log.info("[traceId={}] Gateway Request: {} {} from {}", traceId, method, path, remoteAddress);

        String finalTraceId = traceId;
        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            long duration = System.currentTimeMillis() - startTime;
            HttpStatus statusCode = exchange.getResponse().getStatusCode();
            int status = statusCode != null ? statusCode.value() : DEFAULT_STATUS_CODE;
            log.info("[traceId={}] Gateway Response: {} {} - status={} duration={}ms",
                    finalTraceId, method, path, status, duration);
        }));
    }

    /**
     * 获取过滤器执行顺序
     *
     * @return 过滤器顺序值
     */
    @Override
    public int getOrder() {
        return ORDER;
    }

    /**
     * 解析客户端远程 IP 地址
     *
     * @param request 当前 HTTP 请求
     * @return 客户端 IP 地址，无法获取时返回 "unknown"
     */
    private String resolveRemoteAddress(ServerHttpRequest request) {
        InetSocketAddress remoteAddress = request.getRemoteAddress();
        if (remoteAddress == null || remoteAddress.getAddress() == null) {
            return UNKNOWN_ADDRESS;
        }
        return remoteAddress.getAddress().getHostAddress();
    }
}
