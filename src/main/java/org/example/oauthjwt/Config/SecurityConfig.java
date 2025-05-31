package org.example.oauthjwt.Config;

import jakarta.servlet.http.HttpServletRequest;
import org.example.oauthjwt.Jwt.JWTFilter;
import org.example.oauthjwt.Jwt.JWTUtil;
import org.example.oauthjwt.OAuth.CustomSuccessHandler;
import org.example.oauthjwt.Service.CustomOAuth2UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;
    private final JWTUtil jwtUtil;

    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService,
                          CustomSuccessHandler customSuccessHandler,
                          JWTUtil jwtUtil) {
        this.customOAuth2UserService = customOAuth2UserService;
        this.customSuccessHandler = customSuccessHandler;
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //CORS 설정
        //CORS는 Cross-Origin Resource Sharing의 약자로,
        //다른 도메인에서 리소스에 접근할 수 있도록 허용하는 설정입니다.
        http
                //corsCustomizer를 사용하여 CORS 설정을 커스터마이징할 수 있습니다.
                .cors((corsCustomizer) -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    // 이 메소드는 HttpServletRequest를 인자로 받아 CORS 구성을 반환합니다.
                    // 이 설정은 모든 출처에서의 요청을 허용하고, 모든 HTTP 메서드와 헤더를 허용합니다.
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration configuration = new CorsConfiguration();

                        // 허용할 출처를 설정합니다.
                        // 여기서는 http://localhost:3000에서 오는 요청을 허용합니다.
                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        // 모든 HTTP 메서드를 허용합니다.
                        // GET, POST, PUT, DELETE, OPTIONS 등 모든 메서드를 허용합니다.
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        // Allow credentials는 쿠키, 인증 헤더 등을 허용하는 설정입니다.
                        configuration.setAllowCredentials(true);
                        // 모든 헤더를 허용합니다.
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        // CORS 요청에 대한 응답 헤더를 설정합니다.
                        configuration.setMaxAge(3600L);

                        // Exposed headers는 클라이언트가 접근할 수 있는 응답 헤더를 설정합니다.
                        // 여기서는 Authorization, Set-Cookie 헤더를 노출시킵니다.
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));
                        configuration.setAllowedHeaders(Collections.singletonList("Set-Cookie"));

                        return configuration;
                    }
                }));

        //csrf disable
        //csrf는 기본적으로 CSRF 공격을 방지하기 위해 활성화되어 있지만,
        //OAuth2 인증을 사용할 때는 CSRF 보호가 필요하지 않으므로 비활성화합니다.
        http
                .csrf((auth) -> auth.disable());

        //From 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        //HTTP Basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        //JWT 필터 설정
        // JWT 필터를 UsernamePasswordAuthenticationFilter 이전에 추가하여
        // JWT 토큰을 검증하고 인증 정보를 설정합니다.
        http
                .addFilterBefore(new JWTFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        //oauth2
        http
                .oauth2Login((oauth2) -> oauth2
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(customOAuth2UserService))
                        .successHandler(customSuccessHandler)
                );//필터에 customOAuth2UserService 사용 설정
        //successHandler에 customSuccessHandler 사용 설정
        //이 핸들러는 인증 성공 후 JWT를 생성하고 쿠키에 담아 클라이언트로 전달함.

        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/").permitAll()
                        .anyRequest().authenticated());

        //세션 설정 : STATELESS
        // Spring Security는 기본적으로 세션을 사용하여 인증 정보를 저장하지만,
        // OAuth2 인증을 사용할 때는 세션을 사용하지 않도록 설정합니다.
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
