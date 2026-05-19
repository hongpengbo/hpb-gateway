package com.api.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * 全局跨域配置
 *
 * @author api
 * @date 2026/04/10
 */
@Configuration
public class CorsConfig {

    /**
     * 预检请求缓存时长（秒），1 小时
     */
    private static final long PREFLIGHT_MAX_AGE_SECONDS = 3600L;

    /**
     * 配置全局跨域过滤器
     * <p>
     * 允许所有来源、常用 HTTP 方法、所有请求头，并暴露 traceId 和 Authorization 响应头
     *
     * @return CorsWebFilter 跨域过滤器实例
     */
    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();
        // 允许的来源，生产环境建议指定具体域名
        config.addAllowedOriginPattern("*");
        // 允许的请求方法
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        // 允许的请求头
        config.addAllowedHeader("*");
        // 允许携带凭证（Cookie 等）
        config.setAllowCredentials(true);
        // 预检请求缓存时间
        config.setMaxAge(PREFLIGHT_MAX_AGE_SECONDS);
        // 允许暴露给前端的响应头
        config.setExposedHeaders(Arrays.asList("X-Trace-Id", "Authorization"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsWebFilter(source);
    }
}
