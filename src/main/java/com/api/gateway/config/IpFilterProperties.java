package com.api.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * IP 黑白名单配置属性类
 * <p>
 * 支持从 application.yml 加载 IP 黑白名单配置，包括：
 * 1. 白名单模式：仅允许白名单中的 IP 访问
 * 2. 黑名单模式：禁止黑名单中的 IP 访问
 * 3. 支持单个 IP 和 CIDR 网段格式（如 192.168.1.0/24）
 *
 * @author api
 * @date 2026/04/10
 */
@Data
@Component
@ConfigurationProperties(prefix = "gateway.ip-filter")
public class IpFilterProperties {

    /**
     * 是否启用 IP 白名单过滤
     */
    private boolean whitelistEnabled = false;

    /**
     * 是否启用 IP 黑名单过滤
     */
    private boolean blacklistEnabled = false;

    /**
     * IP 白名单列表
     * 支持格式：
     * - 单个 IP：192.168.1.1
     * - CIDR 网段：192.168.1.0/24
     */
    private List<String> whitelist = new ArrayList<>();

    /**
     * IP 黑名单列表
     * 支持格式：
     * - 单个 IP：192.168.1.1
     * - CIDR 网段：192.168.1.0/24
     */
    private List<String> blacklist = new ArrayList<>();

    /**
     * 被拦截时的响应消息
     */
    private String rejectMessage = "访问被拒绝：IP 地址不在允许范围内";
}
