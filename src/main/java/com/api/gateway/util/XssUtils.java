package com.api.gateway.util;

import java.util.regex.Pattern;

/**
 * XSS 攻击防护工具类
 * <p>
 * 通过正则匹配移除常见的 XSS 攻击载荷，包括：
 * - script 标签及内容
 * - 事件处理属性（onerror、onload、onclick 等）
 * - javascript: 伪协议
 * - eval() 表达式
 * - expression() CSS 表达式
 * - vbscript: 伪协议
 * - 其他危险 HTML 标签（iframe、object、embed、form、input）
 *
 * @author api
 * @date 2026/04/10
 */
public class XssUtils {

    private XssUtils() {
        // 工具类禁止实例化
    }

    /**
     * XSS 匹配规则列表，按优先级排序
     */
    private static final Pattern[] XSS_PATTERNS = {
            // <script>...</script> 标签及其内容
            Pattern.compile("<script(.*?)>(.*?)</script>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // <script ... /> 自闭合形式
            Pattern.compile("<script(.*?)/>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // <script ...> 开始标签（未闭合情况）
            Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // </script> 结束标签
            Pattern.compile("</script>", Pattern.CASE_INSENSITIVE),
            // javascript: 伪协议
            Pattern.compile("javascript\\s*:", Pattern.CASE_INSENSITIVE),
            // vbscript: 伪协议
            Pattern.compile("vbscript\\s*:", Pattern.CASE_INSENSITIVE),
            // eval(...) 表达式
            Pattern.compile("eval\\s*\\(", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // expression(...) CSS 表达式
            Pattern.compile("expression\\s*\\(", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // on* 事件属性（如 onerror、onload、onclick 等）
            Pattern.compile("\\bon\\w+\\s*=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // <iframe> 标签
            Pattern.compile("<iframe(.*?)>(.*?)</iframe>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            Pattern.compile("<iframe(.*?)/>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // <object> 标签
            Pattern.compile("<object(.*?)>(.*?)</object>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // <embed> 标签
            Pattern.compile("<embed(.*?)>(.*?)</embed>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            Pattern.compile("<embed(.*?)/>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // <form> 标签
            Pattern.compile("<form(.*?)>(.*?)</form>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            // <input> 标签
            Pattern.compile("<input(.*?)/>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
            Pattern.compile("<input(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
    };

    /**
     * 清理字符串中的 XSS 恶意内容
     *
     * @param value 原始字符串
     * @return 清理后的安全字符串，如果输入为 null 则返回 null
     */
    public static String clean(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        String cleaned = value;
        for (Pattern pattern : XSS_PATTERNS) {
            cleaned = pattern.matcher(cleaned).replaceAll("");
        }
        return cleaned;
    }

    /**
     * 判断字符串中是否包含 XSS 恶意内容
     *
     * @param value 待检测字符串
     * @return 如果包含 XSS 内容返回 true，否则返回 false
     */
    public static boolean containsXss(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        for (Pattern pattern : XSS_PATTERNS) {
            if (pattern.matcher(value).find()) {
                return true;
            }
        }
        return false;
    }
}
