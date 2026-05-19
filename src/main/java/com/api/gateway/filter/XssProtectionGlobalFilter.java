package com.api.gateway.filter;

import com.api.gateway.util.XssUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 全局 XSS 防护过滤器
 * <p>
 * 在网关层统一拦截并清理请求中可能携带的 XSS 恶意脚本，防护范围包括：
 * <ul>
 *     <li>URL 查询参数（Query Parameters）</li>
 *     <li>请求体（仅针对 Content-Type 为 application/json 的 POST/PUT/PATCH 请求）</li>
 * </ul>
 * <p>
 * 过滤器优先级设置在 TraceId 和 Logging 过滤器之后执行
 *
 * @author api
 * @date 2026/04/10
 */
@Slf4j
@Component
public class XssProtectionGlobalFilter implements GlobalFilter, Ordered {

    /**
     * 过滤器顺序：在 Logging 过滤器之后执行
     */
    public static final int ORDER = LoggingGlobalFilter.ORDER + 1;

    /**
     * 处理请求，清理查询参数和请求体中的 XSS 恶意内容
     *
     * @param exchange 当前请求上下文
     * @param chain    过滤器链
     * @return 响应完成信号
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // 1. 清理查询参数中的 XSS 内容
        ServerWebExchange sanitizedExchange = cleanQueryParams(exchange, request);

        // 将清理后的 exchange 赋值为 final 变量，供后续 lambda 使用
        final ServerWebExchange finalExchange = sanitizedExchange;

        // 2. 对含有请求体的请求（POST/PUT/PATCH），清理 JSON 请求体中的 XSS 内容
        if (shouldCleanBody(request)) {
            return cleanRequestBody(finalExchange, chain);
        }

        return chain.filter(finalExchange);
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
     * 清理查询参数中的 XSS 恶意内容
     * <p>
     * 遍历所有查询参数的 key 和 value，通过 XssUtils 进行清理，
     * 如果检测到修改则重建 URI
     *
     * @param exchange 当前请求上下文
     * @param request  当前 HTTP 请求
     * @return 清理后的 exchange，如果未发现 XSS 则返回原始 exchange
     */
    private ServerWebExchange cleanQueryParams(ServerWebExchange exchange, ServerHttpRequest request) {
        URI originalUri = request.getURI();
        String originalQuery = originalUri.getRawQuery();
        if (originalQuery == null || originalQuery.isEmpty()) {
            return exchange;
        }

        Map<String, List<String>> originalParams = request.getQueryParams();
        Map<String, List<String>> cleanedParams = new LinkedHashMap<>(originalParams.size());
        boolean queryModified = false;

        for (Map.Entry<String, List<String>> entry : originalParams.entrySet()) {
            String cleanedKey = XssUtils.clean(entry.getKey());
            List<String> cleanedValues = entry.getValue().stream()
                    .map(XssUtils::clean)
                    .collect(Collectors.toList());
            cleanedParams.put(cleanedKey, cleanedValues);

            if (!cleanedKey.equals(entry.getKey())) {
                queryModified = true;
            }
            for (int i = 0; i < entry.getValue().size(); i++) {
                if (!entry.getValue().get(i).equals(cleanedValues.get(i))) {
                    queryModified = true;
                    break;
                }
            }
        }

        if (!queryModified) {
            return exchange;
        }

        log.warn("XSS 检测到查询参数中含有恶意内容，已清理: {}", originalUri.getPath());
        URI cleanedUri = rebuildUri(originalUri, cleanedParams);
        ServerHttpRequest cleanedRequest = request.mutate().uri(cleanedUri).build();
        return exchange.mutate().request(cleanedRequest).build();
    }

    /**
     * 使用清理后的参数重建 URI
     *
     * @param originalUri   原始 URI
     * @param cleanedParams 清理后的参数 Map
     * @return 重建后的 URI
     */
    private URI rebuildUri(URI originalUri, Map<String, List<String>> cleanedParams) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUri(originalUri).replaceQuery(null);
        for (Map.Entry<String, List<String>> entry : cleanedParams.entrySet()) {
            for (String value : entry.getValue()) {
                builder.queryParam(entry.getKey(), value);
            }
        }
        return builder.build(true).toUri();
    }

    /**
     * 判断是否需要清理请求体
     * <p>
     * 仅对 POST/PUT/PATCH 方法且 Content-Type 为 application/json 的请求进行清理
     *
     * @param request 当前 HTTP 请求
     * @return 需要清理返回 true，否则返回 false
     */
    private boolean shouldCleanBody(ServerHttpRequest request) {
        HttpMethod method = request.getMethod();
        MediaType contentType = request.getHeaders().getContentType();
        boolean hasBody = HttpMethod.POST.equals(method)
                || HttpMethod.PUT.equals(method)
                || HttpMethod.PATCH.equals(method);
        boolean isJson = contentType != null && contentType.isCompatibleWith(MediaType.APPLICATION_JSON);
        return hasBody && isJson;
    }

    /**
     * 清理 JSON 请求体中的 XSS 恶意内容
     * <p>
     * 读取请求体内容，通过 XssUtils 清理后重新包装为新的请求体
     *
     * @param exchange 当前请求上下文
     * @param chain    过滤器链
     * @return 响应完成信号
     */
    private Mono<Void> cleanRequestBody(ServerWebExchange exchange, GatewayFilterChain chain) {
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .flatMap(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);

                    String body = new String(bytes, StandardCharsets.UTF_8);
                    if (XssUtils.containsXss(body)) {
                        log.warn("XSS 检测到请求体中含有恶意内容，已清理: {}",
                                exchange.getRequest().getURI().getPath());
                    }
                    String cleanedBody = XssUtils.clean(body);

                    byte[] cleanedBytes = cleanedBody.getBytes(StandardCharsets.UTF_8);
                    ServerHttpRequest mutatedRequest = buildCleanedRequest(
                            exchange.getRequest(), cleanedBytes);

                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                })
                .switchIfEmpty(chain.filter(exchange));
    }

    /**
     * 构建带有清理后请求体的新请求对象
     *
     * @param originalRequest 原始请求
     * @param cleanedBytes    清理后的请求体字节数组
     * @return 包含清理后请求体的新请求对象
     */
    private ServerHttpRequest buildCleanedRequest(ServerHttpRequest originalRequest, byte[] cleanedBytes) {
        DataBufferFactory dataBufferFactory = new DefaultDataBufferFactory();
        DataBuffer cleanedBuffer = dataBufferFactory.wrap(cleanedBytes);

        return new ServerHttpRequestDecorator(originalRequest) {
            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.just(cleanedBuffer);
            }

            @Override
            public HttpHeaders getHeaders() {
                HttpHeaders headers = new HttpHeaders();
                headers.putAll(super.getHeaders());
                headers.setContentLength(cleanedBytes.length);
                return headers;
            }
        };
    }
}
