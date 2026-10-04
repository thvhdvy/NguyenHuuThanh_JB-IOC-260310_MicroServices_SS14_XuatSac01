package com.thanhnguyen.identityservice.exception;

public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException() {
        super("Bad credentials");
    }
}
