package com.api.gateway.util;

import lombok.extern.slf4j.Slf4j;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * IP 地址工具类
 * <p>
 * 提供 IP 地址解析、CIDR 网段匹配等功能
 *
 * @author api
 * @date 2026/04/10
 */
@Slf4j
public class IpUtils {

    /**
     * 从请求头中获取客户端真实 IP 地址
     * <p>
     * 优先从 X-Forwarded-For 等代理头中获取，如果没有则使用远程地址
     *
     * @param remoteAddr     远程地址
     * @param xForwardedFor  X-Forwarded-For 头
     * @param xRealIp        X-Real-IP 头
     * @return 客户端真实 IP 地址
     */
    public static String getClientIp(String remoteAddr, String xForwardedFor, String xRealIp) {
        String ip = null;

        // 优先使用 X-Real-IP
        if (xRealIp != null && !xRealIp.isEmpty() && !"unknown".equalsIgnoreCase(xRealIp)) {
            ip = xRealIp.trim();
        }

        // 其次使用 X-Forwarded-For 的第一个 IP
        if (ip == null && xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
            // X-Forwarded-For 可能包含多个 IP，取第一个
            int index = xForwardedFor.indexOf(',');
            if (index != -1) {
                ip = xForwardedFor.substring(0, index).trim();
            } else {
                ip = xForwardedFor.trim();
            }
        }

        // 如果没有代理头，使用远程地址
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = remoteAddr;
        }

        // 处理 IPv6 本地地址
        if (ip != null && ip.startsWith("0:0:0:0:0:0:0:1")) {
            ip = "127.0.0.1";
        }

        // 去除端口（如果有）
        if (ip != null && ip.contains(":")) {
            // 检查是否是 IPv6 地址
            if (!ip.startsWith("[") && ip.split(":").length <= 2) {
                // IPv4:port 格式
                ip = ip.substring(0, ip.lastIndexOf(":"));
            }
        }

        return ip;
    }

    /**
     * 检查 IP 是否匹配指定的规则
     * <p>
     * 支持单个 IP 和 CIDR 网段格式
     *
     * @param clientIp 客户端 IP
     * @param rule     IP 规则（单个 IP 或 CIDR 网段）
     * @return 是否匹配
     */
    public static boolean isIpMatch(String clientIp, String rule) {
        if (clientIp == null || rule == null || clientIp.isEmpty() || rule.isEmpty()) {
            return false;
        }

        // 去除空格
        clientIp = clientIp.trim();
        rule = rule.trim();

        // 检查是否是 CIDR 格式
        if (rule.contains("/")) {
            return isIpInCidr(clientIp, rule);
        }

        // 单个 IP 直接比较
        return clientIp.equals(rule);
    }

    /**
     * 检查 IP 是否在 CIDR 网段内
     *
     * @param clientIp 客户端 IP
     * @param cidr     CIDR 网段（如 192.168.1.0/24）
     * @return 是否在网段内
     */
    public static boolean isIpInCidr(String clientIp, String cidr) {
        try {
            String[] parts = cidr.split("/");
            if (parts.length != 2) {
                return false;
            }

            String networkIp = parts[0];
            int prefixLength = Integer.parseInt(parts[1]);

            // 仅支持 IPv4
            if (!isValidIpv4(clientIp) || !isValidIpv4(networkIp)) {
                return false;
            }

            int clientIpInt = ipToInt(clientIp);
            int networkIpInt = ipToInt(networkIp);

            // 计算掩码
            int mask = 0xFFFFFFFF << (32 - prefixLength);

            // 比较网络部分
            return (clientIpInt & mask) == (networkIpInt & mask);
        } catch (Exception e) {
            log.warn("Invalid CIDR format: {}, error: {}", cidr, e.getMessage());
            return false;
        }
    }

    /**
     * 将 IPv4 地址转换为整数
     *
     * @param ip IPv4 地址
     * @return 整数表示
     */
    private static int ipToInt(String ip) {
        String[] parts = ip.split("\\.");
        int result = 0;
        for (int i = 0; i < 4; i++) {
            result = (result << 8) | Integer.parseInt(parts[i]);
        }
        return result;
    }

    /**
     * 检查是否是有效的 IPv4 地址
     *
     * @param ip IP 地址
     * @return 是否有效
     */
    private static boolean isValidIpv4(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        try {
            for (String part : parts) {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    return false;
                }
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
