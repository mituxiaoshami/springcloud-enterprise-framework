package com.enterprise.framework.starter.tracing.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TracingController {


    private static Logger logger = LoggerFactory.getLogger(TracingController.class);


    @RequestMapping(value = "/tracing")
    public String tracing() throws InterruptedException {
        logger.info("tracing from [{}]", "result");
        Thread.sleep(100);
        return "tracing";
    }


    @RequestMapping(value = "/open")
    public String open() throws InterruptedException {
        long startTime = System.currentTimeMillis();
        logger.info("open from [{}]", startTime);
        Thread.sleep(200);
        return "open";
    }

}