package com.culturalCenter.AuthorizationServer.Utils;


/**
 * 授权异常枚举类
 */
public enum AuthErrorEnum {
    ACCESS_DENIED(4301,"权限不足"),
    LOGIN_NAME_ERROR(4302,"用户名不存在"),
    LOGIN_PASSWORD_ERROR(4304,"密码错误"),
    AUTH_HEADER_ERROR(4305,"不合法的token验证"),
    TOKEN_NEEDED(4306,"无token信息，访问当前资源请先登录"),
    TOKEN_EXPIRED(4307,"token已过期，请重新登录"),
    TOKEN_REFRESHED(4308,"token已被刷新，用户在其他地方登录"),
    ALREADY_LOGIN(4309,"用户已在其他设备登录"),
    SSO_AUTHENTICATE_FAILED(4310,"当前用户未通过sso服务验证")
    ;

    private Integer code;

    private String message;

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    AuthErrorEnum(Integer code, String message) {
        this.code = code;
        this.message = message;
    }
}
