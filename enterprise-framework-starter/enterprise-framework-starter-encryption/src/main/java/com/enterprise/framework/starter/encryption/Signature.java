package com.enterprise.framework.starter.encryption;


import java.lang.annotation.*;


/**
 * 声明Api加密注解
 * Documented: 注解将包含在 JavaDoc中
 * ElementType.METHOD: 注解只能作用于方法上
 * RetentionPolicy.RUNTIME: 该注解生存期是运行时
 */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Signature {


}
