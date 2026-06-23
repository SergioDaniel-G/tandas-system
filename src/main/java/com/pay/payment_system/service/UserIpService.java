package com.pay.payment_system.service;

import com.pay.payment_system.entity.UserTrustedIp;

import java.util.List;

public interface UserIpService {

    List<UserTrustedIp> findAllUserIps();

    boolean isIpTrusted(String email, String ipAddress);

    void addOrUpdateTrustedIp(String email, String ipAddress);
}
