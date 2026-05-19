package com.api.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 会员服务网关启动类
 *
 * @author api
 * @date 2026/04/10
 */
@SpringBootApplication
public class ApiMain {

    /**
     * 应用程序入口方法
     *
     * @param args 启动参数
     */
    public static void main(String[] args) {
        SpringApplication.run(ApiMain.class, args);
    }
}