package com.api.gateway.config;

import com.alibaba.cloud.nacos.NacosConfigManager;
import com.alibaba.nacos.api.config.listener.Listener;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Nacos 配置监听器
 * <p>
 * 监听 Nacos 配置变更，当配置发生变化时只输出变更的配置项
 * 从 Environment 读取 application.yml 中已配置的属性
 *
 * @author api
 * @date 2026/04/10
 */
@Slf4j
@Component
public class NacosConfigListener implements ApplicationRunner {

    @Autowired
    private NacosConfigManager nacosConfigManager;

    @Autowired
    private Environment environment;

    // 保存上一次配置，用于对比变更
    private final AtomicReference<String> lastConfig = new AtomicReference<>("");

    @Override
    public void run(ApplicationArguments args) throws Exception {
        // 从 Environment 读取 application.yml 中配置的属性
        String dataId = environment.getProperty("spring.application.name", "hpb-gateway");
        String group = environment.getProperty("spring.cloud.nacos.config.group", "DEFAULT_GROUP");
        String namespace = environment.getProperty("spring.cloud.nacos.config.namespace", "");
        String fileExtension = environment.getProperty("spring.cloud.nacos.config.file-extension", "yml");

        String fullDataId = dataId + "." + fileExtension;

        // 添加配置监听器
        nacosConfigManager.getConfigService().addListener(
                fullDataId,
                group,
                new Listener() {
                    @Override
                    public Executor getExecutor() {
                        return null;
                    }

                    @Override
                    public void receiveConfigInfo(String config) {
                        String previous = lastConfig.getAndSet(config);
                        if (previous.isEmpty()) {
                            // 首次加载，只记录不打印变更
                            log.info("Nacos 配置首次加载 [DataId={}, Group={}, Namespace={}]", fullDataId, group, namespace);
                            return;
                        }

                        // 对比并打印变更
                        String diff = compareConfig(previous, config);
                        if (!diff.isEmpty()) {
                            log.info("Nacos 配置已变更 [DataId={}, Group={}, Namespace={}]，变更内容：{}",
                                    fullDataId, group, namespace, diff);
                        }
                    }
                }
        );

        log.info("Nacos 配置监听器已启动，监听配置：DataId={}, Group={}, Namespace={}",
                fullDataId, group, namespace);
    }

    /**
     * 对比新旧配置，找出变更的行
     */
    private String compareConfig(String oldConfig, String newConfig) {
        String[] oldLines = oldConfig.split("\n");
        String[] newLines = newConfig.split("\n");
        StringBuilder diff = new StringBuilder();

        // 简单行对比，找出新增或修改的行
        for (String newLine : newLines) {
            String trimmed = newLine.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            boolean found = false;
            for (String oldLine : oldLines) {
                if (oldLine.trim().equals(trimmed)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                diff.append("[+ ").append(trimmed).append("] ");
            }
        }

        // 找出删除的行
        for (String oldLine : oldLines) {
            String trimmed = oldLine.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            boolean found = false;
            for (String newLine : newLines) {
                if (newLine.trim().equals(trimmed)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                diff.append("[- ").append(trimmed).append("] ");
            }
        }

        return diff.toString();
    }
}
