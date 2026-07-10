package com.pay.payment_system.controller;

import static com.pay.payment_system.config.LogSanitizer.safe;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    // INTERCEPTS METHOD ARGUMENT VALIDATION EXCEPTIONS COMPILES FIELD ERRORS AND LOGS AUDIT WARNS

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<String> handleValidationExceptions(MethodArgumentNotValidException ex) {

        String errorMessage = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> error.getDefaultMessage())
                .collect(Collectors.joining(", "));

        log.warn("VALIDATION FAILED: Request blocked due to invalid fields. Reason: {}", safe(errorMessage));

        return ResponseEntity.badRequest().body(errorMessage);
    }

    // CAPTURES MALFORMED UNREADABLE HTTP REQUEST BODIES TO PREVENT PARSING ERRORS AND SHIELD SYSTEM SCHEMA

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<String> handleHttpMessageNotReadableException(HttpMessageNotReadableException ex) {

        log.warn("MALFORMED JSON: Request blocked due to unreadable HTTP message body. Technical reason: {}", safe(ex.getMessage()));

        return ResponseEntity.badRequest().body("Malformed or invalid JSON request body.");
    }

    // HANDLES PERSISTENCE INTERACTION CONFLICTS AND DATA INTEGRITY VIOLATIONS EMITTING A STATUS CONFLICT RESPONSE

    @ExceptionHandler(org.springframework.dao.DataIntegrityViolationException.class)
    public ResponseEntity<String> handleDataIntegrityViolationException(org.springframework.dao.DataIntegrityViolationException ex) {
        log.error("DATABASE ERROR: Integrity violation. Technical reason: {}", safe(ex.getMessage()));

        return ResponseEntity.status(HttpStatus.CONFLICT).body("Data conflict: The record could not be saved.");
    }

    // BACKSTOPS ALL UNCAUGHT GENERIC EXCEPTIONS LOGGING CRITICAL COMPONENT METADATA AND MASKING ROOT CAUSES FOR CLIENTS

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleAllUncaughtExceptions(Exception ex) {
        String exceptionType = ex.getClass().getSimpleName();
        String rootCause = ex.getMessage() != null ? ex.getMessage() : "No message provided";


        log.error("CRITICAL ERROR: [{}] - Uncaught exception handled. Technical reason: {}",
                safe(exceptionType), safe(rootCause));

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("An unexpected error occurred on the server.");
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException ex) {
        String rootCause = ex.getMessage() != null ? ex.getMessage() : "Invalid argument";

        log.warn("BUSINESS VALIDATION FAILED: Request rejected. Reason: {}", safe(rootCause));

        if ("PHONE_ALREADY_IN_USE".equals(rootCause)) {
            return ResponseEntity.badRequest()
                    .body("The mobile number is already linked to another account.");
        }

        return ResponseEntity.badRequest().body(rootCause);
    }

    @ExceptionHandler(org.springframework.web.servlet.resource.NoResourceFoundException.class)
    public ResponseEntity<String> handleNoResourceFoundException(org.springframework.web.servlet.resource.NoResourceFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Resource not found.");
    }
}
