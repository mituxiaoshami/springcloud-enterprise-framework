package com.enterprise.framework.starter.encryption.aspect;


import com.alibaba.fastjson.JSON;
import com.enterprise.framework.starter.encryption.config.RSAConfigProperties;
import com.enterprise.framework.starter.encryption.constants.SignConstant;
import com.enterprise.framework.starter.encryption.util.HttpUtil;
import com.enterprise.framework.starter.encryption.util.RSAUtil;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import java.util.Objects;
import java.util.SortedMap;

@Aspect
@Slf4j
@Configuration
public class SignatureAspect {


    @Autowired
    private RSAConfigProperties rsaConfigProperties;


    /**
     * 把Signature注解作为切点
     */
    @Pointcut("@annotation(com.enterprise.framework.starter.encryption.Signature)")
    public void signature() {

    }


    /**
     * 在切点之前织入
     */
    @Before("signature()")
    public void doBefore() {
        // 打印请求相关参数
        log.info("========================================== 接口验签名开始 ==========================================");
    }




    /**
     * 环绕
     * @param proceedingJoinPoint 切点
     * @return 切点方法返回
     */
    @Around("signature()")
    public Object doAround(ProceedingJoinPoint proceedingJoinPoint) throws Throwable {
        // 从获取RequestAttributes中获取HttpServletRequest的信息
        HttpServletRequest request = (HttpServletRequest) Objects.requireNonNull(RequestContextHolder.getRequestAttributes()).resolveReference(RequestAttributes.REFERENCE_REQUEST);
        switch (Objects.requireNonNull(request).getMethod()) {
            case "GET":
                SortedMap<String, String> getParamMap = HttpUtil.getUrlParamsForGet(request);
                if (!RSAUtil.verifySign(JSON.toJSONString(getParamMap), request.getHeader(SignConstant.SIGN_HEADER), rsaConfigProperties.getPublicKey())) {
                    throw new RuntimeException("sign not allow, please check param");
                }
                break;
            case "POST":
            case "PUT":
            case "DELETE":
                // 对解密后的request body 进行首字母排序
                SortedMap<String, String> sortedMap = HttpUtil.getUrlParamsForPost(request);
                if (!RSAUtil.verifySign(JSON.toJSONString(sortedMap), request.getHeader(SignConstant.SIGN_HEADER), rsaConfigProperties.getPublicKey())) {
                    throw new RuntimeException("sign not allow, please check param");
                }
                break;
            default:
                break;
        }
        return proceedingJoinPoint.proceed(proceedingJoinPoint.getArgs());
    }




}
