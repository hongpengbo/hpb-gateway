package com.api.gateway.common;

import lombok.Data;

import java.io.Serializable;

/**
 * 统一响应结果封装类
 * <p>
 * 所有 API 接口返回的统一数据结构，包含状态码、提示信息、响应数据三个字段
 *
 * @param <T> 响应数据的类型
 * @author api
 * @date 2026/04/10
 */
@Data
public class Result<T> implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 成功状态码
     */
    public static final int SUCCESS_CODE = 200;

    /**
     * 失败状态码
     */
    public static final int ERROR_CODE = 500;

    /**
     * 业务异常状态码
     */
    public static final int BUSINESS_ERROR_CODE = 400;

    /**
     * 未授权状态码
     */
    public static final int UNAUTHORIZED_CODE = 401;

    /**
     * 禁止访问状态码
     */
    public static final int FORBIDDEN_CODE = 403;

    /**
     * 资源不存在状态码
     */
    public static final int NOT_FOUND_CODE = 404;

    /**
     * 请求参数错误状态码
     */
    public static final int PARAM_ERROR_CODE = 422;

    /**
     * 成功默认提示信息
     */
    public static final String SUCCESS_MESSAGE = "操作成功";

    /**
     * 失败默认提示信息
     */
    public static final String ERROR_MESSAGE = "操作失败";

    /**
     * 状态码
     */
    private Integer code;

    /**
     * 提示信息
     */
    private String message;

    /**
     * 响应数据
     */
    private T data;

    /**
     * 时间戳
     */
    private Long timestamp;

    /**
     * 私有构造方法，强制使用静态工厂方法创建实例
     */
    private Result() {
        this.timestamp = System.currentTimeMillis();
    }

    /**
     * 创建成功响应结果（无数据）
     *
     * @param <T> 响应数据类型
     * @return 成功响应结果
     */
    public static <T> Result<T> success() {
        return success(null);
    }

    /**
     * 创建成功响应结果（带数据）
     *
     * @param data 响应数据
     * @param <T>  响应数据类型
     * @return 成功响应结果
     */
    public static <T> Result<T> success(T data) {
        Result<T> result = new Result<>();
        result.setCode(SUCCESS_CODE);
        result.setMessage(SUCCESS_MESSAGE);
        result.setData(data);
        return result;
    }

    /**
     * 创建成功响应结果（带自定义消息和数据）
     *
     * @param message 提示信息
     * @param data    响应数据
     * @param <T>     响应数据类型
     * @return 成功响应结果
     */
    public static <T> Result<T> success(String message, T data) {
        Result<T> result = new Result<>();
        result.setCode(SUCCESS_CODE);
        result.setMessage(message);
        result.setData(data);
        return result;
    }

    /**
     * 创建失败响应结果（默认错误信息）
     *
     * @param <T> 响应数据类型
     * @return 失败响应结果
     */
    public static <T> Result<T> error() {
        return error(ERROR_MESSAGE);
    }

    /**
     * 创建失败响应结果（自定义错误信息）
     *
     * @param message 错误信息
     * @param <T>     响应数据类型
     * @return 失败响应结果
     */
    public static <T> Result<T> error(String message) {
        return error(ERROR_CODE, message);
    }

    /**
     * 创建失败响应结果（自定义状态码和错误信息）
     *
     * @param code    状态码
     * @param message 错误信息
     * @param <T>     响应数据类型
     * @return 失败响应结果
     */
    public static <T> Result<T> error(Integer code, String message) {
        Result<T> result = new Result<>();
        result.setCode(code);
        result.setMessage(message);
        return result;
    }

    /**
     * 创建业务异常响应结果
     *
     * @param message 错误信息
     * @param <T>     响应数据类型
     * @return 业务异常响应结果
     */
    public static <T> Result<T> businessError(String message) {
        return error(BUSINESS_ERROR_CODE, message);
    }

    /**
     * 创建参数错误响应结果
     *
     * @param message 错误信息
     * @param <T>     响应数据类型
     * @return 参数错误响应结果
     */
    public static <T> Result<T> paramError(String message) {
        return error(PARAM_ERROR_CODE, message);
    }

    /**
     * 判断是否成功响应
     *
     * @return 成功返回 true，否则返回 false
     */
    public boolean isSuccess() {
        return SUCCESS_CODE == this.code;
    }
}
