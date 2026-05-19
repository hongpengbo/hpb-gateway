package com.api.gateway.exception;

import com.api.gateway.common.Result;
import lombok.Getter;

/**
 * 业务异常类
 * <p>
 * 用于封装业务逻辑层面的异常信息，支持自定义错误码和错误信息
 *
 * @author api
 * @date 2026/04/10
 */
@Getter
public class BusinessException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * 错误码
     */
    private final Integer code;

    /**
     * 构造业务异常（使用默认业务错误码）
     *
     * @param message 错误信息
     */
    public BusinessException(String message) {
        super(message);
        this.code = Result.BUSINESS_ERROR_CODE;
    }

    /**
     * 构造业务异常（自定义错误码）
     *
     * @param code    错误码
     * @param message 错误信息
     */
    public BusinessException(Integer code, String message) {
        super(message);
        this.code = code;
    }

    /**
     * 构造业务异常（自定义错误码和异常原因）
     *
     * @param code    错误码
     * @param message 错误信息
     * @param cause   原始异常
     */
    public BusinessException(Integer code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    /**
     * 构造业务异常（默认错误码和异常原因）
     *
     * @param message 错误信息
     * @param cause   原始异常
     */
    public BusinessException(String message, Throwable cause) {
        super(message, cause);
        this.code = Result.BUSINESS_ERROR_CODE;
    }
}
