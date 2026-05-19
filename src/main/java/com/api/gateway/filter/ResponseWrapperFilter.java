package com.api.gateway.filter;

import com.api.gateway.common.Result;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * 统一响应包装过滤器
 * <p>
 * 将下游服务的响应统一包装为 Result 格式，包括：
 * <ul>
 *     <li>成功响应：包装为 Result.success(data)</li>
 *     <li>错误响应：转换为 Result.error(code, message)</li>
 * </ul>
 * <p>
 * 注意：仅对 Content-Type 为 application/json 的响应进行包装
 *
 * @author api
 * @date 2026/04/10
 */
@Slf4j
@Component
public class ResponseWrapperFilter implements GlobalFilter, Ordered {

    /**
     * JSON 序列化工具
     */
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 过滤器顺序：在 SQL 注入过滤器之后执行
     */
    public static final int ORDER = SqlInjectionProtectionGlobalFilter.ORDER + 1;

    /**
     * 包装响应体，统一返回 Result 格式
     *
     * @param exchange 当前请求上下文
     * @param chain    过滤器链
     * @return 响应完成信号
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpResponse originalResponse = exchange.getResponse();

        // 只处理 JSON 响应
        MediaType contentType = originalResponse.getHeaders().getContentType();
        if (!shouldWrapResponse(contentType)) {
            return chain.filter(exchange);
        }

        // 包装响应对象
        ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                if (body instanceof Flux) {
                    Flux<? extends DataBuffer> fluxBody = (Flux<? extends DataBuffer>) body;
                    return super.writeWith(fluxBody.buffer().map(dataBuffers -> {
                        // 合并所有数据缓冲区
                        DataBufferFactory bufferFactory = new DefaultDataBufferFactory();
                        DataBuffer joined = bufferFactory.join(dataBuffers);

                        byte[] content = new byte[joined.readableByteCount()];
                        joined.read(content);
                        DataBufferUtils.release(joined);

                        String responseBody = new String(content, StandardCharsets.UTF_8);
                        String wrappedBody = wrapResponse(responseBody, originalResponse.getStatusCode());

                        byte[] wrappedBytes = wrappedBody.getBytes(StandardCharsets.UTF_8);
                        originalResponse.getHeaders().setContentLength(wrappedBytes.length);

                        return bufferFactory.wrap(wrappedBytes);
                    }));
                }
                return super.writeWith(body);
            }
        };

        return chain.filter(exchange.mutate().response(decoratedResponse).build());
    }

    /**
     * 判断是否需要包装响应
     * <p>
     * 仅对 application/json 类型的响应进行包装
     *
     * @param contentType 响应内容类型
     * @return 需要包装返回 true，否则返回 false
     */
    private boolean shouldWrapResponse(MediaType contentType) {
        if (contentType == null) {
            return false;
        }
        return contentType.isCompatibleWith(MediaType.APPLICATION_JSON);
    }

    /**
     * 包装响应体为统一格式
     * <p>
     * 如果响应已经是 Result 格式则直接返回，否则根据状态码包装
     *
     * @param responseBody 原始响应体
     * @param statusCode   HTTP 状态码
     * @return 包装后的 JSON 字符串
     */
    private String wrapResponse(String responseBody, HttpStatus statusCode) {
        // 如果已经是 Result 格式，直接返回
        if (isAlreadyWrapped(responseBody)) {
            return responseBody;
        }

        Result<Object> result;
        int code = statusCode != null ? statusCode.value() : Result.SUCCESS_CODE;

        if (code >= 200 && code < 300) {
            // 成功响应，尝试解析为对象
            Object data = parseJson(responseBody);
            result = Result.success(data);
        } else {
            // 错误响应
            result = Result.error(code, responseBody);
        }

        return toJson(result);
    }

    /**
     * 判断响应是否已经是 Result 格式
     *
     * @param responseBody 响应体字符串
     * @return 是 Result 格式返回 true，否则返回 false
     */
    private boolean isAlreadyWrapped(String responseBody) {
        try {
            return responseBody.contains("\"code\"") && responseBody.contains("\"message\"") && responseBody.contains("\"data\"");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 将 JSON 字符串解析为对象
     *
     * @param json JSON 字符串
     * @return 解析后的对象，解析失败返回原字符串
     */
    private Object parseJson(String json) {
        try {
            return objectMapper.readValue(json, Object.class);
        } catch (JsonProcessingException e) {
            // 解析失败，返回原始字符串
            return json;
        }
    }

    /**
     * 将 Result 对象序列化为 JSON 字符串
     *
     * @param result Result 对象
     * @return JSON 字符串
     */
    private String toJson(Result<?> result) {
        try {
            return objectMapper.writeValueAsString(result);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize Result to JSON", e);
            return "{\"code\":500,\"message\":\"响应序列化失败\",\"data\":null}";
        }
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
}
