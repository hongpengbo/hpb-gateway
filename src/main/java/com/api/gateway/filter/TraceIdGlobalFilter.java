package com.api.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * 全局 traceId 过滤器
 * <p>
 * 1. 如果请求头中已携带 traceId，则复用；否则生成新的 traceId
 * 2. 将 traceId 放入请求头，传递给下游微服务
 * 3. 将 traceId 放入响应头，方便客户端排查问题
 * 4. 将 traceId 放入 MDC，方便日志输出
 *
 * @author api
 * @date 2026/04/10
 */
@Slf4j
@Component
public class TraceIdGlobalFilter implements GlobalFilter, Ordered {

    /**
     * traceId 在 HTTP 请求头/响应头中的 key
     */
    public static final String TRACE_ID_HEADER = "X-Trace-Id";

    /**
     * traceId 在 MDC 和 exchange 属性中的 key
     */
    public static final String TRACE_ID_MDC_KEY = "traceId";

    /**
     * 过滤器顺序：最高优先级，确保在所有业务过滤器之前执行
     */
    public static final int ORDER = Ordered.HIGHEST_PRECEDENCE;

    /**
     * 处理请求，注入 traceId 到请求头、响应头和 MDC
     *
     * @param exchange 当前请求上下文
     * @param chain    过滤器链
     * @return 响应完成信号
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 优先从请求头中获取 traceId，如果没有则生成新的
        String traceId = exchange.getRequest().getHeaders().getFirst(TRACE_ID_HEADER);
        if (traceId == null || traceId.isEmpty()) {
            traceId = generateTraceId();
        }

        // 将 traceId 注入请求头，传递给下游服务
        String finalTraceId = traceId;
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header(TRACE_ID_HEADER, finalTraceId)
                .build();

        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(mutatedRequest)
                .build();

        // 将 traceId 存入 exchange 属性，供其他过滤器使用
        mutatedExchange.getAttributes().put(TRACE_ID_MDC_KEY, finalTraceId);

        // 设置 MDC 用于日志输出
        MDC.put(TRACE_ID_MDC_KEY, finalTraceId);
        log.debug("TraceId generated/reused: {}", finalTraceId);

        return chain.filter(mutatedExchange).then(Mono.fromRunnable(() -> {
            // 将 traceId 写入响应头
            ServerHttpResponse response = mutatedExchange.getResponse();
            if (!response.isCommitted()) {
                response.getHeaders().set(TRACE_ID_HEADER, finalTraceId);
            }
            MDC.remove(TRACE_ID_MDC_KEY);
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
     * 生成 traceId，使用 UUID 去掉横线的 32 位字符串
     *
     * @return 32 位 traceId 字符串
     */
    private String generateTraceId() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
