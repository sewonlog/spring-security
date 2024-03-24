package com.example.securitypractice.config;

import com.example.securitypractice.jwt.Authority;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.io.IOException;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.security.cors.allow.methods:1,2,3,4,5,6}")
    private String[] allowedMethods;

    private final String[] excludedEndPoints = {
            "/*"
    };

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        //return (web) -> web.ignoring().antMatchers("/ignore1", "/ignore2");
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authz) -> authz
                        .anyRequest().authenticated()
                )
                .formLogin(withDefaults())
                .httpBasic(withDefaults());

        http.csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                // 동일 도메인에서는 iframe 접근 가능하도록 X-Frame-Options는 sameOrigin으로 설정
                .headers(headersConfig -> headersConfig
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                //cors 설정
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests((authorizeRequest) -> {
                    authorizeRequest
                            .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                            .requestMatchers(excludedEndPoints).permitAll()
                            .requestMatchers("/**").hasRole(Authority.ROLE_USER.getAuthority())
                            .anyRequest().authenticated();
                })
                //에러 핸들링 설정
                .exceptionHandling(handling ->
                        handling
                                //인증 실패 혹은 인증 헤더에 없는 경우 401 응답
                                .authenticationEntryPoint(authenticationEntryPoint)
                                //권한에 대한 처리 에러 403 응답
                                .accessDeniedHandler(accessDeniedHandler));
        return http.build();
    }

    // CORS 설정 메서드
    private CorsConfigurationSource corsConfigurationSource(){
        return request -> {
            CorsConfiguration config = new CorsConfiguration();
            //config.setAllowedOrigins(List.of(allowedOriginPaths));
            config.setAllowedMethods(List.of(allowedMethods));
            config.setAllowedHeaders(List.of(HttpHeaders.AUTHORIZATION, HttpHeaders.CONTENT_TYPE, HttpHeaders.SET_COOKIE, HttpHeaders.ACCEPT, HttpHeaders.ACCEPT_LANGUAGE, HttpHeaders.CONTENT_LANGUAGE));
            config.setAllowCredentials(true);
            config.setMaxAge(3600L);
            return config;
        };
    }

    // 권한 처리에 대한 에러 응답 핸들링
    private final AuthenticationEntryPoint authenticationEntryPoint = ((request, response, authException) -> {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    });

    // 인증 실패 경우 에러 응답 핸들링
    private final AccessDeniedHandler accessDeniedHandler = ((request, response, accessDeniedException) -> {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
    });


}
