package com.api.gateway.filter;

import com.api.gateway.common.Result;
import com.api.gateway.util.SqlInjectionUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * 全局 SQL 注入防护过滤器
 * <p>
 * 在网关层统一检测请求中是否携带 SQL 注入攻击载荷，检测范围包括：
 * <ul>
 *     <li>URL 查询参数（Query Parameters）的 key 和 value</li>
 *     <li>请求体（仅针对 Content-Type 为 application/json 的 POST/PUT/PATCH 请求）</li>
 * </ul>
 * <p>
 * 与 XSS 防护不同，SQL 注入一旦检测到立即拒绝请求并返回 400 Bad Request，
 * 因为清理 SQL 注入内容可能破坏正常业务数据的语义
 * <p>
 * 过滤器优先级设置在 XSS 防护过滤器之后执行
 *
 * @author api
 * @date 2026/04/10
 */
@Slf4j
@Component
public class SqlInjectionProtectionGlobalFilter implements GlobalFilter, Ordered {

    /**
     * JSON 序列化工具
     */
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * SQL 注入拦截提示信息
     */
    private static final String SQL_INJECTION_REJECTION_MESSAGE = "请求包含非法字符，已被拦截";

    /**
     * 过滤器顺序：在 XSS 防护过滤器之后执行
     */
    public static final int ORDER = XssProtectionGlobalFilter.ORDER + 1;

    /**
     * 处理请求，检测查询参数和请求体中的 SQL 注入攻击
     *
     * @param exchange 当前请求上下文
     * @param chain    过滤器链
     * @return 响应完成信号
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // 1. 检测查询参数中是否包含 SQL 注入
        if (containsSqlInjectionInQueryParams(request, path)) {
            return reject(exchange);
        }

        // 2. 对含有请求体的请求（POST/PUT/PATCH），检测 JSON 请求体
        if (shouldCheckBody(request)) {
            return checkRequestBody(exchange, chain, path);
        }

        return chain.filter(exchange);
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
     * 检测查询参数中是否包含 SQL 注入攻击载荷
     *
     * @param request 当前 HTTP 请求
     * @param path    请求路径，用于日志记录
     * @return 检测到 SQL 注入返回 true，否则返回 false
     */
    private boolean containsSqlInjectionInQueryParams(ServerHttpRequest request, String path) {
        Map<String, List<String>> queryParams = request.getQueryParams();
        for (Map.Entry<String, List<String>> entry : queryParams.entrySet()) {
            if (SqlInjectionUtils.containsSqlInjection(entry.getKey())) {
                log.warn("SQL 注入检测拦截 - 查询参数名含恶意内容: path={}, param={}, matchedPattern={}",
                        path, entry.getKey(), SqlInjectionUtils.getMatchedPattern(entry.getKey()));
                return true;
            }
            for (String value : entry.getValue()) {
                if (SqlInjectionUtils.containsSqlInjection(value)) {
                    log.warn("SQL 注入检测拦截 - 查询参数值含恶意内容: path={}, param={}, matchedPattern={}",
                            path, entry.getKey(), SqlInjectionUtils.getMatchedPattern(value));
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 判断是否需要检测请求体
     * <p>
     * 仅对 POST/PUT/PATCH 方法且 Content-Type 为 application/json 的请求进行检测
     *
     * @param request 当前 HTTP 请求
     * @return 需要检测返回 true，否则返回 false
     */
    private boolean shouldCheckBody(ServerHttpRequest request) {
        HttpMethod method = request.getMethod();
        MediaType contentType = request.getHeaders().getContentType();
        boolean hasBody = HttpMethod.POST.equals(method)
                || HttpMethod.PUT.equals(method)
                || HttpMethod.PATCH.equals(method);
        boolean isJson = contentType != null && contentType.isCompatibleWith(MediaType.APPLICATION_JSON);
        return hasBody && isJson;
    }

    /**
     * 检测 JSON 请求体中是否包含 SQL 注入攻击载荷
     * <p>
     * 读取请求体内容进行检测，如果安全则重新包装请求体继续传递
     *
     * @param exchange 当前请求上下文
     * @param chain    过滤器链
     * @param path     请求路径，用于日志记录
     * @return 响应完成信号
     */
    private Mono<Void> checkRequestBody(ServerWebExchange exchange, GatewayFilterChain chain, String path) {
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .flatMap(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);

                    String body = new String(bytes, StandardCharsets.UTF_8);
                    if (SqlInjectionUtils.containsSqlInjection(body)) {
                        log.warn("SQL 注入检测拦截 - 请求体含恶意内容: path={}, matchedPattern={}",
                                path, SqlInjectionUtils.getMatchedPattern(body));
                        return reject(exchange);
                    }

                    // 请求体安全，重新包装请求体（因为已被消费）
                    ServerHttpRequest mutatedRequest = rebuildRequest(exchange.getRequest(), bytes);
                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                })
                .switchIfEmpty(chain.filter(exchange));
    }

    /**
     * 重新包装请求体，解决请求体被消费后无法再次读取的问题
     *
     * @param originalRequest 原始请求
     * @param bodyBytes       请求体字节数组
     * @return 包含重新包装请求体的新请求对象
     */
    private ServerHttpRequest rebuildRequest(ServerHttpRequest originalRequest, byte[] bodyBytes) {
        DataBuffer buffer = originalRequest.getHeaders().getContentType() != null
                ? new org.springframework.core.io.buffer.DefaultDataBufferFactory().wrap(bodyBytes)
                : new org.springframework.core.io.buffer.DefaultDataBufferFactory().wrap(bodyBytes);

        return new ServerHttpRequestDecorator(originalRequest) {
            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.just(buffer);
            }

            @Override
            public HttpHeaders getHeaders() {
                HttpHeaders headers = new HttpHeaders();
                headers.putAll(super.getHeaders());
                headers.setContentLength(bodyBytes.length);
                return headers;
            }
        };
    }

    /**
     * 拒绝请求，返回 400 Bad Request 及统一格式的错误信息
     *
     * @param exchange 当前请求上下文
     * @return 响应完成信号
     */
    private Mono<Void> reject(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.BAD_REQUEST);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Result<Void> result = Result.businessError(SQL_INJECTION_REJECTION_MESSAGE);
        byte[] responseBytes;
        try {
            responseBytes = objectMapper.writeValueAsBytes(result);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize SQL injection rejection response", e);
            responseBytes = "{\"code\":400,\"message\":\"请求包含非法字符，已被拦截\"}".getBytes(StandardCharsets.UTF_8);
        }

        DataBuffer buffer = response.bufferFactory().wrap(responseBytes);
        return response.writeWith(Mono.just(buffer));
    }
}
