package com.api.gateway.exception;

import com.api.gateway.common.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

/**
 * 全局异常处理器
 * <p>
 * 统一处理系统中抛出的各类异常，将异常转换为标准的 Result 响应格式
 *
 * @author api
 * @date 2026/04/10
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * 处理业务异常
     *
     * @param ex       业务异常
     * @param exchange 请求上下文
     * @return 统一错误响应
     */
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<Result<Void>> handleBusinessException(BusinessException ex, ServerWebExchange exchange) {
        log.warn("BusinessException occurred: path={}, code={}, message={}",
                exchange.getRequest().getURI().getPath(), ex.getCode(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Result.error(ex.getCode(), ex.getMessage()));
    }

    /**
     * 处理响应状态异常（如 404 Not Found）
     *
     * @param ex       响应状态异常
     * @param exchange 请求上下文
     * @return 统一错误响应
     */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Result<Void>> handleResponseStatusException(ResponseStatusException ex, ServerWebExchange exchange) {
        HttpStatus status = ex.getStatus();
        String reason = ex.getReason();
        log.warn("ResponseStatusException occurred: path={}, status={}, message={}",
                exchange.getRequest().getURI().getPath(), status, reason);

        int statusValue = status != null ? status.value() : HttpStatus.INTERNAL_SERVER_ERROR.value();
        HttpStatus responseStatus = status != null ? status : HttpStatus.INTERNAL_SERVER_ERROR;

        return ResponseEntity.status(responseStatus)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Result.error(statusValue, reason));
    }

    /**
     * 处理非法参数异常
     *
     * @param ex       非法参数异常
     * @param exchange 请求上下文
     * @return 统一错误响应
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Result<Void>> handleIllegalArgumentException(IllegalArgumentException ex, ServerWebExchange exchange) {
        log.warn("IllegalArgumentException occurred: path={}, message={}",
                exchange.getRequest().getURI().getPath(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Result.paramError(ex.getMessage()));
    }

    /**
     * 处理所有其他未捕获的异常
     *
     * @param ex       异常
     * @param exchange 请求上下文
     * @return 统一错误响应
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Result<Void>> handleException(Exception ex, ServerWebExchange exchange) {
        log.error("Unexpected exception occurred: path={}", exchange.getRequest().getURI().getPath(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Result.error("系统繁忙，请稍后重试"));
    }
}
