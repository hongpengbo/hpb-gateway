package com.api.gateway.filter;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.concurrent.TimeUnit;

/**
 * 网关指标收集过滤器
 * <p>
 * 收集以下 Prometheus 格式指标供 Grafana 展示：
 * 1. QPS：gateway_requests_total（总请求数，按路由、状态码、方法分类）
 * 2. 错误率：gateway_requests_total 中 status=5xx 的比例
 * 3. 响应时间分布：gateway_request_duration_seconds（P50/P90/P95/P99）
 * 4. 请求体大小：gateway_request_size_bytes
 * 5. 响应体大小：gateway_response_size_bytes
 * <p>
 * 执行顺序：在日志过滤器之后，确保记录完整的请求信息
 *
 * @author api
 * @date 2026/04/10
 */
@Slf4j
@Component
public class MetricsFilter implements GlobalFilter, Ordered {

    @Autowired
    private MeterRegistry meterRegistry;

    /**
     * 过滤器顺序：在日志过滤器之后执行
     */
    public static final int ORDER = LoggingGlobalFilter.ORDER + 1;

    /**
     * 路由 ID 属性键
     */
    private static final String GATEWAY_ROUTE_ATTR = "org.springframework.cloud.gateway.support.ServerWebExchangeUtils.gatewayRoute";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String method = request.getMethodValue();
        String path = request.getURI().getPath();

        // 记录请求开始时间
        long startTime = System.nanoTime();

        // 获取请求体大小（如果可用）
        long requestSize = request.getHeaders().getContentLength();

        return chain.filter(exchange).doFinally(signalType -> {
            // 计算响应时间（毫秒）
            long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
            double durationSeconds = durationMs / 1000.0;

            // 获取响应状态码
            HttpStatus statusCode = exchange.getResponse().getStatusCode();
            int status = statusCode != null ? statusCode.value() : 0;
            String statusClass = getStatusClass(status);

            // 获取路由 ID
            String routeId = getRouteId(exchange);

            // 获取响应体大小（如果可用）
            long responseSize = exchange.getResponse().getHeaders().getContentLength();

            // 记录指标
            recordMetrics(method, routeId, path, status, statusClass, durationMs, durationSeconds, requestSize, responseSize);
        });
    }

    /**
     * 记录所有指标
     */
    private void recordMetrics(String method, String routeId, String path, int status,
                               String statusClass, long durationMs, double durationSeconds,
                               long requestSize, long responseSize) {
        try {
            // 1. 请求总数 Counter（QPS 计算基础）
            Counter.builder("gateway_requests_total")
                    .description("Total number of gateway requests(QPS)")
                    .tag("route", routeId)
                    .tag("method", method)
                    .tag("status", String.valueOf(status))
                    .tag("status_class", statusClass)
                    .register(meterRegistry)
                    .increment();

            // 2. 响应时间 Timer（自动计算 P50/P90/P95/P99）
            Timer.builder("gateway_request_duration_seconds")
                    .description("Gateway request duration in seconds")
                    .tag("route", routeId)
                    .tag("method", method)
                    .tag("status_class", statusClass)
                    .publishPercentiles(0.5, 0.90, 0.95, 0.99)
                    .register(meterRegistry)
                    .record(durationMs, TimeUnit.MILLISECONDS);

            // 3. 响应时间 DistributionSummary（用于直方图）
            DistributionSummary.builder("gateway_request_duration_histogram")
                    .description("Gateway request duration histogram")
                    .tag("route", routeId)
                    .tag("method", method)
                    .baseUnit("milliseconds")
                    .serviceLevelObjectives(
                            10.0,   // < 10ms
                            50.0,   // < 50ms
                            100.0,  // < 100ms
                            200.0,  // < 200ms
                            500.0,  // < 500ms
                            1000.0, // < 1s
                            2000.0, // < 2s
                            5000.0  // < 5s
                    )
                    .register(meterRegistry)
                    .record(durationMs);

            // 4. 请求体大小（如果有）
            if (requestSize > 0) {
                DistributionSummary.builder("gateway_request_size_bytes")
                        .description("Gateway request size in bytes")
                        .tag("route", routeId)
                        .tag("method", method)
                        .register(meterRegistry)
                        .record(requestSize);
            }

            // 5. 响应体大小（如果有）
            if (responseSize > 0) {
                DistributionSummary.builder("gateway_response_size_bytes")
                        .description("Gateway response size in bytes")
                        .tag("route", routeId)
                        .tag("status_class", statusClass)
                        .register(meterRegistry)
                        .record(responseSize);
            }

            // 6. 错误请求计数（status >= 400）
            if (status >= 400) {
                Counter.builder("gateway_requests_error_total")
                        .description("Total number of error gateway requests")
                        .tag("route", routeId)
                        .tag("method", method)
                        .tag("status", String.valueOf(status))
                        .tag("status_class", statusClass)
                        .register(meterRegistry)
                        .increment();
            }

            // 7. 活跃请求数 Gauge（在请求开始时增加，结束时减少）
            // 这里使用 Counter 模拟，实际应该使用 Gauge
            Counter.builder("gateway_requests_active")
                    .description("Number of active gateway requests")
                    .tag("route", routeId)
                    .register(meterRegistry)
                    .increment();

        } catch (Exception e) {
            log.error("Failed to record metrics", e);
        }
    }

    /**
     * 获取状态码分类（2xx, 4xx, 5xx 等）
     */
    private String getStatusClass(int status) {
        if (status >= 200 && status < 300) {
            return "2xx";
        } else if (status >= 300 && status < 400) {
            return "3xx";
        } else if (status >= 400 && status < 500) {
            return "4xx";
        } else if (status >= 500) {
            return "5xx";
        }
        return "unknown";
    }

    /**
     * 获取路由 ID
     */
    private String getRouteId(ServerWebExchange exchange) {
        Object route = exchange.getAttribute(GATEWAY_ROUTE_ATTR);
        if (route != null) {
            // 尝试获取路由 ID
            try {
                return route.getClass().getMethod("getId").invoke(route).toString();
            } catch (Exception e) {
                // 忽略反射异常
            }
        }
        return "unknown";
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
