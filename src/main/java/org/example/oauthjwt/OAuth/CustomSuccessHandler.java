package org.example.oauthjwt.OAuth;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.oauthjwt.Dto.CustomOAuth2User;
import org.example.oauthjwt.Jwt.JWTUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

// Config 이기때문에 @Component 어노테이션을 붙여야 스프링이 인식함
// SimpleUrlAuthenticationSuccessHandler를 상속받아 커스텀 핸들러를 구현
@Component
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JWTUtil jwtUtil;

    public CustomSuccessHandler(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        //OAuth2User
        //인증이 성공하면 CustomOAuth2User를 가져옴
        //CustomOAuth2User는 OAuth2User를 구현한 클래스
        //여기서 사용자 정보를 가져올 수 있음
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();
        String username = customUserDetails.getUsername();

        //Authentication 객체는 인증된 사용자의 정보를 담고 있음
        //인증된 사용자의 권한을 가져옴
        //여기서는 단일 권한만을 가정하고, 첫 번째 권한을 가져옴
        //실제 애플리케이션에서는 여러 권한을 처리할 수 있도록 수정해야 함
        //Authentication 객체에서 권한을 가져옴
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority authority = iterator.next();
        String role = authority.getAuthority();

        //JWT 생성
        String token = jwtUtil.createJwt(username, role, 60 * 60 * 10L);

        //JWT를 쿠키에 담아 클라이언트로 전달
        //쿠키는 HttpOnly로 설정하여 클라이언트 측에서 접근할 수 없도록 함
        //이렇게 하면 클라이언트에서 쿠키를 통해 JWT를 사용할 수 있음
        response.addCookie(createCookie("Authorization", token));
        response.sendRedirect("http://localhost:3000/");
    }

    // 쿠키 생성 메소드
    // 쿠키의 이름과 값을 받아 HttpOnly 속성을 설정하고, 경로를 "/"로 지정
    // 쿠키의 유효 기간을 10시간으로 설정
    public Cookie createCookie(String Key, String value) {
        Cookie cookie = new Cookie(Key, value);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60 * 10); // 10시간
        return cookie;
    }
}