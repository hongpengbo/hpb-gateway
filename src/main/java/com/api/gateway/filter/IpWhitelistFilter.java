package com.api.gateway.filter;

import com.api.gateway.common.Result;
import com.api.gateway.config.IpFilterProperties;
import com.api.gateway.util.IpUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * IP 白名单过滤器
 * <p>
 * 仅允许白名单中配置的 IP 地址访问网关
 * 支持单个 IP 和 CIDR 网段格式（如 192.168.1.0/24）
 * <p>
 * 执行顺序：在 TraceId 过滤器之后，其他业务过滤器之前执行
 *
 * @author api
 * @date 2026/04/10
 */
@Slf4j
@Component
public class IpWhitelistFilter implements GlobalFilter, Ordered {

    @Autowired
    private IpFilterProperties ipFilterProperties;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * 过滤器顺序：在黑名单过滤器之后，其他安全过滤器之前
     * 白名单在黑名单之后检查，用于限制只允许特定 IP 访问
     */
    public static final int ORDER = Ordered.HIGHEST_PRECEDENCE + 20;

    /**
     * 请求头常量
     */
    private static final String HEADER_X_FORWARDED_FOR = "X-Forwarded-For";
    private static final String HEADER_X_REAL_IP = "X-Real-IP";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 如果白名单未启用，直接放行
        if (!ipFilterProperties.isWhitelistEnabled()) {
            return chain.filter(exchange);
        }

        List<String> whitelist = ipFilterProperties.getWhitelist();
        // 如果白名单为空，直接放行
        if (whitelist == null || whitelist.isEmpty()) {
            log.warn("IP whitelist is enabled but empty, allowing all requests");
            return chain.filter(exchange);
        }

        // 获取客户端 IP
        String clientIp = getClientIp(exchange.getRequest());

        // 检查 IP 是否在白名单中
        if (isIpInWhitelist(clientIp, whitelist)) {
            log.debug("IP {} is in whitelist, allowing request", clientIp);
            return chain.filter(exchange);
        }

        // IP 不在白名单中，拒绝访问
        log.warn("IP {} is not in whitelist, rejecting request to {}", clientIp, exchange.getRequest().getURI().getPath());
        return rejectRequest(exchange, clientIp);
    }

    /**
     * 获取客户端真实 IP 地址
     *
     * @param request HTTP 请求
     * @return 客户端 IP
     */
    private String getClientIp(ServerHttpRequest request) {
        String remoteAddr = request.getRemoteAddress() != null 
                ? request.getRemoteAddress().getAddress().getHostAddress() 
                : null;
        String xForwardedFor = request.getHeaders().getFirst(HEADER_X_FORWARDED_FOR);
        String xRealIp = request.getHeaders().getFirst(HEADER_X_REAL_IP);

        return IpUtils.getClientIp(remoteAddr, xForwardedFor, xRealIp);
    }

    /**
     * 检查 IP 是否在白名单中
     *
     * @param clientIp  客户端 IP
     * @param whitelist 白名单列表
     * @return 是否在白名单中
     */
    private boolean isIpInWhitelist(String clientIp, List<String> whitelist) {
        for (String rule : whitelist) {
            if (IpUtils.isIpMatch(clientIp, rule)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 拒绝请求，返回 403 错误
     *
     * @param exchange 请求上下文
     * @param clientIp 客户端 IP
     * @return 拒绝响应
     */
    private Mono<Void> rejectRequest(ServerWebExchange exchange, String clientIp) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String message = ipFilterProperties.getRejectMessage();
        Result<Void> result = Result.error(Result.FORBIDDEN_CODE, message);

        String responseBody;
        try {
            responseBody = objectMapper.writeValueAsString(result);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize error response", e);
            responseBody = "{\"code\":403,\"message\":\"Access Denied\",\"data\":null,\"timestamp\":" + System.currentTimeMillis() + "}";
        }

        DataBuffer buffer = response.bufferFactory().wrap(responseBody.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
