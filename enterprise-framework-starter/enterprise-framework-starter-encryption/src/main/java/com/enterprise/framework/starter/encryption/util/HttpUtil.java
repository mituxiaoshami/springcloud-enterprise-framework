package com.enterprise.framework.starter.encryption.util;

import com.alibaba.fastjson.JSONObject;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Map;
import java.util.Objects;
import java.util.SortedMap;
import java.util.TreeMap;

public class HttpUtil {

    /**
     * 将URL请求参数转换成Map
     * @param httpServletRequest web请求
     * @return 排好序的参数
     */
    public static SortedMap<String, String> getUrlParamsForGet(HttpServletRequest httpServletRequest) {
        String param = "";
        SortedMap<String, String> result = new TreeMap<>();
        if (!StringUtils.hasLength(httpServletRequest.getQueryString())) {
            return result;
        }
        try {
            param = URLDecoder.decode(httpServletRequest.getQueryString(), "utf-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        String[] params = param.split("&");
        for (String s : params) {
            int index = s.indexOf("=");
            result.put(s.substring(0, index), s.substring(index + 1));
        }
        return result;
    }


    /**
     * 将URL请求参数转换成Map
     * @param httpServletRequest web请求
     * @return 排好序的参数
     */
    public static SortedMap<String, String> getUrlParamsForPost(HttpServletRequest httpServletRequest) throws IOException {

        SortedMap<String, String> sortedMap = new TreeMap<>();
        if (Objects.isNull(httpServletRequest) || Objects.equals(httpServletRequest.getContentType(), MediaType.APPLICATION_JSON_VALUE)) {
            throw new RuntimeException("request is null or http content type value is error");
        }
        BufferedReader reader = httpServletRequest.getReader();
        StringBuilder body = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            body.append(line);
        }
        // 解析JSON字符串
        JSONObject jsonObject = JSONObject.parseObject(body.toString());
        for(Map.Entry<String, Object> entry : jsonObject.entrySet()) {
            sortedMap.put(entry.getKey(), entry.getValue().toString());
        }
        return sortedMap;
    }

}
