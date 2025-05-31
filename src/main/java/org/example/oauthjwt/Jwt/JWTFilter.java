package org.example.oauthjwt.Jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.oauthjwt.Dto.CustomOAuth2User;
import org.example.oauthjwt.Dto.UserDto;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.rmi.server.ServerCloneException;

// OncePerRequestFilter는 매 요청마다 한번 필터링을 수행하는 필터입니다.
// 이 필터를 사용하여 JWT 토큰을 검증하고, 인증 정보를 설정할 수 있습니다.
public class JWTFilter extends OncePerRequestFilter {
    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws IOException, ServletException {

        // request에서 Authorization 헤더를 가져옴
        // 쿠키에서 Authorization 값을 가져옴
        String authorization = null;
        Cookie[] cookies = request.getCookies();

        // 쿠키의 Authorization 값을 찾음
        // 쿠키의 Value를 authorization 변수에 저장
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("Authorization")) {
                authorization = cookie.getValue();
            }
        }

        //Authorization 헤더를 검증
        // authorization이 null이면 필터 체인을 계속 진행
        // 토큰이 없으면 인증을 하지 않고 다음 필터로 넘어감
        if (authorization == null) {
            System.out.println("token null");
            filterChain.doFilter(request, response);
            return; //해당 조건에 해당되면 메소드 종료 필수
        }

        String token = authorization;
        // 토큰이 만료되었는지 검증
        if (jwtUtil.isExpired(token)) {
            System.out.println("token expired");
            filterChain.doFilter(request, response);
            return; // 해당 조건에 해당되면 메소드 종료 필수
        }

        // 토큰에서 username과 role을 가져옴
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // UserDto 를 생성하여 값 설정
        UserDto userDto = new UserDto();
        userDto.setUsername(username);
        userDto.setRole(role);

        // UserDetails에 회원 정보 객체 담기
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDto);

        // 스프링 시큐리티 인증 토큰 생성
        Authentication authtoken = new UsernamePasswordAuthenticationToken(
                customOAuth2User, null, customOAuth2User.getAuthorities());

        // 세션에 사용자 등록
        // SecurityContextHolder.getContext()는 현재 스레드의 보안 컨텍스트를 가져옵니다.
        // setAuthentication 메소드를 사용하여 인증 정보를 설정합니다.
        SecurityContextHolder.getContext().setAuthentication(authtoken);
        filterChain.doFilter(request, response);
    }
}
