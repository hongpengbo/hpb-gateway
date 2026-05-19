package com.api.gateway.util;

import java.util.regex.Pattern;

/**
 * SQL 注入防护工具类
 * <p>
 * 通过正则匹配检测常见的 SQL 注入攻击载荷，包括：
 * <ul>
 *     <li>SQL 关键字组合（SELECT...FROM、INSERT INTO、UPDATE...SET、DELETE FROM、DROP TABLE 等）</li>
 *     <li>联合查询注入（UNION SELECT）</li>
 *     <li>逻辑永真条件（OR 1=1、OR 'a'='a' 等）</li>
 *     <li>注释符号（--、#、/&#42;...&#42;/）</li>
 *     <li>批量执行分号（;）后跟 SQL 关键字</li>
 *     <li>时间盲注函数（SLEEP、BENCHMARK、WAITFOR）</li>
 *     <li>信息探测函数（LOAD_FILE、INTO OUTFILE/DUMPFILE）</li>
 *     <li>系统函数调用（CHAR()、CONCAT()、HEX()、UNHEX() 等）</li>
 * </ul>
 * <p>
 * 注意：本工具类仅用于网关层的前置检测，不替代后端参数化查询等根本性防护措施
 *
 * @author api
 * @date 2026/04/10
 */
public class SqlInjectionUtils {

    private SqlInjectionUtils() {
        // 工具类禁止实例化
    }

    /**
     * SQL 注入匹配规则列表
     * <p>
     * 使用 \b 单词边界避免误匹配正常业务数据中的普通单词，
     * 所有规则不区分大小写
     */
    private static final Pattern[] SQL_INJECTION_PATTERNS = {
            // UNION SELECT 联合查询注入
            Pattern.compile("\\bUNION\\b.*\\bSELECT\\b", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),

            // SELECT ... FROM 查询语句
            Pattern.compile("\\bSELECT\\b.*\\bFROM\\b", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),

            // INSERT INTO 插入语句
            Pattern.compile("\\bINSERT\\b.*\\bINTO\\b", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),

            // UPDATE ... SET 更新语句
            Pattern.compile("\\bUPDATE\\b.*\\bSET\\b", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),

            // DELETE FROM 删除语句
            Pattern.compile("\\bDELETE\\b.*\\bFROM\\b", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),

            // DROP TABLE / DROP DATABASE 删表删库
            Pattern.compile("\\bDROP\\b.*\\b(TABLE|DATABASE)\\b", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),

            // ALTER TABLE 修改表结构
            Pattern.compile("\\bALTER\\b.*\\bTABLE\\b", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),

            // TRUNCATE TABLE 清空表
            Pattern.compile("\\bTRUNCATE\\b.*\\bTABLE\\b", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),

            // CREATE TABLE / CREATE DATABASE 创建表或库
            Pattern.compile("\\bCREATE\\b.*\\b(TABLE|DATABASE)\\b", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),

            // EXEC / EXECUTE 执行存储过程（SQL Server）
            Pattern.compile("\\bEXEC(UTE)?\\b", Pattern.CASE_INSENSITIVE),

            // 单引号逻辑永真条件：OR 'a'='a'、OR ''='
            Pattern.compile("\\bOR\\b\\s+['\"].*['\"]\\s*=\\s*['\"]", Pattern.CASE_INSENSITIVE),

            // 数字逻辑永真条件：OR 1=1、OR 2=2
            Pattern.compile("\\bOR\\b\\s+\\d+\\s*=\\s*\\d+", Pattern.CASE_INSENSITIVE),

            // AND 逻辑永真/永假条件：AND 1=1、AND 1=2
            Pattern.compile("\\bAND\\b\\s+\\d+\\s*=\\s*\\d+", Pattern.CASE_INSENSITIVE),

            // SQL 单行注释：-- 后跟空格或结尾
            Pattern.compile("--\\s"),

            // MySQL 注释符号 #
            Pattern.compile("#.*$", Pattern.MULTILINE),

            // SQL 块注释：/* ... */
            Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL),

            // 分号后跟 SQL 关键字（批量执行攻击）
            Pattern.compile(";\\s*\\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|EXEC)\\b", Pattern.CASE_INSENSITIVE),

            // 时间盲注：SLEEP()、BENCHMARK()
            Pattern.compile("\\b(SLEEP|BENCHMARK)\\s*\\(", Pattern.CASE_INSENSITIVE),

            // SQL Server 时间盲注：WAITFOR DELAY
            Pattern.compile("\\bWAITFOR\\b.*\\bDELAY\\b", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),

            // 文件操作：LOAD_FILE()
            Pattern.compile("\\bLOAD_FILE\\s*\\(", Pattern.CASE_INSENSITIVE),

            // 文件导出：INTO OUTFILE / INTO DUMPFILE
            Pattern.compile("\\bINTO\\b.*\\b(OUTFILE|DUMPFILE)\\b", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),

            // 字符串拼接/编码函数：CHAR()、CONCAT()、HEX()、UNHEX()
            Pattern.compile("\\b(CHAR|CONCAT|HEX|UNHEX)\\s*\\(", Pattern.CASE_INSENSITIVE),

            // 信息探测函数：DATABASE()、VERSION()、USER()、CURRENT_USER()
            Pattern.compile("\\b(DATABASE|VERSION|USER|CURRENT_USER)\\s*\\(\\s*\\)", Pattern.CASE_INSENSITIVE),
    };

    /**
     * 检测字符串中是否包含 SQL 注入攻击载荷
     *
     * @param value 待检测字符串
     * @return 如果检测到 SQL 注入内容返回 true，否则返回 false
     */
    public static boolean containsSqlInjection(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        for (Pattern pattern : SQL_INJECTION_PATTERNS) {
            if (pattern.matcher(value).find()) {
                return true;
            }
        }
        return false;
    }

    /**
     * 获取匹配到的 SQL 注入规则描述（用于日志记录）
     *
     * @param value 待检测字符串
     * @return 匹配到的正则表达式字符串，未匹配则返回 null
     */
    public static String getMatchedPattern(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        for (Pattern pattern : SQL_INJECTION_PATTERNS) {
            if (pattern.matcher(value).find()) {
                return pattern.pattern();
            }
        }
        return null;
    }
}
