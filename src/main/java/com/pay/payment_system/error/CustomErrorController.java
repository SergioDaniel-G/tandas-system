package com.pay.payment_system.error;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class CustomErrorController implements ErrorController {

    @RequestMapping("/error")
    public String handleError(HttpServletRequest request) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);

        if (status instanceof Integer statusCode) {
            return switch (statusCode) {
                case 403 -> "error/403";
                case 404 -> "error/404";
                case 500 -> "error/500";
                default  -> "error/error";
            };
        }

        return "error/error";
    }
}