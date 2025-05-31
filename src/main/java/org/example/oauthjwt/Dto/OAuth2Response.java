package org.example.oauthjwt.Dto;

public interface OAuth2Response {
    // OAuth2 제공자 이름 (예: "naver", "kakao", "google")
    String getProvider();
    // OAuth2 제공자에서 제공하는 사용자 ID
    String getProviderId();
    // 사용자 이메일
    String getEmail();
    // 사용자 이름
    String getName();
}
