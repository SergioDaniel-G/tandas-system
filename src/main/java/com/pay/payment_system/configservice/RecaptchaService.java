package com.pay.payment_system.configservice;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class RecaptchaService {

    @Value("${google.recaptcha.secret}")
    private String secretKey;

    @Value("${google.recaptcha.url}")
    private String verifyUrl;

    private final RestTemplate restTemplate;

    /**
     * VALIDATES THE RECAPTCHA TOKEN WITH GOOGLE'S API AND ENFORCES HUMAN SCORE LIMITS.
     */
    public boolean validate(String responseToken) {
        if (responseToken == null || responseToken.trim().isEmpty()) {
            log.warn("RECAPTCHA: empty token received");
            return false;
        }

        try {
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("secret", secretKey);
            requestBody.add("response", responseToken);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestBody, headers);

            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    verifyUrl,
                    HttpMethod.POST,
                    request,
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            );

            Map<String, Object> result = response.getBody();

            boolean success = result != null && Boolean.TRUE.equals(result.get("success"));

            if (!success) {
                log.warn("RECAPTCHA FAILED: Google API responded with failure. Result: {}", result);
                return false;
            }

            if (result.containsKey("score")) {
                double score = Double.parseDouble(result.get("score").toString());

                if (score < 0.5) {
                    log.warn("SECURITY ALERT: reCAPTCHA blocked a suspected automated bot attempt. Score: {}", score);
                    return false;
                }
            }

            log.info("RECAPTCHA SUCCESS: Token and human score validated successfully.");
            return true;

        } catch (Exception e) {
            log.error("RECAPTCHA ERROR: Communication with Google API failed. Message: {}", e.getMessage());
            return false;
        }
    }
}