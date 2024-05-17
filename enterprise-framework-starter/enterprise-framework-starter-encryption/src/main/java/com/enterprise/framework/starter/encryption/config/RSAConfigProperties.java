package com.enterprise.framework.starter.encryption.config;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
public class RSAConfigProperties {


    /**
     * rsa公钥
     */
    @Value("${rsa.publicKey}")
    private String publicKey;


    /**
     * rsa私钥
     */
    @Value("${rsa.privateKey}")
    private String privateKey;


}
