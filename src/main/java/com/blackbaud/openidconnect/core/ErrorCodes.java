package com.blackbaud.openidconnect.core;

public enum ErrorCodes implements com.blackbaud.boot.exception.ErrorCodes {
    MISSING_OR_INVALID_AUTHORIZATION_TOKEN(1);

    ErrorCodes(int code) {
        this.code = code;
    }

    private int code;

    @Override
    public String makeErrorCode() {
        return String.format("OIDC-%04d", this.code);
    }
}
