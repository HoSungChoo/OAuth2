package com.spring.oauth2.dto;

import java.util.Map;

public class NaverResponse implements OAuth2Response{
    private final Map<String, Object> attribute;

    // 네이버는 다음과 같은 JSON 데이터 형식을 가진다. resultcode=00, message=success, response={id=123, name=hozzi03, ...}
    public NaverResponse(Map<String, Object> attribute){
        this.attribute = (Map<String, Object>) attribute.get("response");
    }
    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getProviderId() {
        return attribute.get("id").toString();
    }

    @Override
    public String getEmail() {
        return attribute.get("email").toString();
    }

    @Override
    public String getName() {
        return attribute.get("name").toString();
    }
}
