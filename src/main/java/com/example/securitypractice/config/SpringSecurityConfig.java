package com.example.securitypractice.config;

import com.example.securitypractice.jwt.Authority;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SpringSecurityConfig {

    private final String[] excludedEndPoints = {
            ""
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(request -> request
                        .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
                        .anyRequest().authenticated()	// 어떠한 요청이라도 인증필요
                )
                .formLogin(login -> login	// form 방식 로그인 사용
                        .defaultSuccessUrl("/view/dashboard", true)	// 성공 시 dashboard로
                        .permitAll()	// 대시보드 이동이 막히면 안되므로 얘는 허용
                )
                .logout(withDefaults());	// 로그아웃은 기본설정으로 (/logout으로 인증해제)

                /*.httpBasic().disable()
                .formLogin().disable()
                .headers().frameOptions().disable()
                //cors 설정
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .and()
                //.csrf(AbstractHttpConfigurer::disable)
                .and()
                .authorizeHttpRequests((authorizeRequest) -> {
                    authorizeRequest
                            .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                            .requestMatchers(excludedEndPoints).permitAll()
                            .requestMatchers("/**").hasRole(Authority.ROLE_USER.getAuthority())
                            .anyRequest().authenticated();
                })
                // 에러 핸들링 설정 - authenticationEntryPoint, accessDeniedHandler
                .exceptionHandling(handling ->
                        handling
                                // 인증 실패 혹은 인증 헤더에 없는 경우 401 응답
                                .authenticationEntryPoint(authenticationEntryPoint)
                                // 권한에 대한 처리 에러 403 응답
                                .accessDeniedHandler(accessDeniedHandler))
                // 커스텀 필터 설정 추가
                .addFilterBefore(new JwtAuthenticationFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class);*/

        return http.build();
    }

    // CORS 설정 메서드
    private CorsConfigurationSource corsConfigurationSource(){
        return request -> {
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedOrigins(Collections.singletonList("*"));
            config.setAllowedMethods(List.of("POST", "PUT", "GET", "OPTIONS", "DELETE", "PATCH"));
            config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Set-Cookie"));
            config.setMaxAge(3600L);
            return config;
        };
    }

    // 인증 실패 경우 에러 응답 핸들링
    private final AccessDeniedHandler accessDeniedHandler = ((request, response, accessDeniedException) -> {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
    });

    // 권한 처리에 대한 에러 응답 핸들링
    private final AuthenticationEntryPoint authenticationEntryPoint = ((request, response, authException) -> {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    });
}
