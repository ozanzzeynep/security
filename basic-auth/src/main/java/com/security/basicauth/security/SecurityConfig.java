package com.security.basicauth.security;

import com.security.basicauth.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity security) throws Exception{
        security
                .headers(x-> x.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(x->
                        x.requestMatchers("/public/**").permitAll()
                                .requestMatchers("/private/admin/**").hasRole(Role.ROLE_ADMIN.getValue())
                        .requestMatchers("/private/**").hasAnyRole(Role.ROLE_USER.getValue(),
                                        Role.ROLE_ADMIN.getValue(),
                                        Role.ROLE_MOD.getValue(),
                                Role.ROLE_FSK.getValue())
                                .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(x->x.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));

        return security.build();
    }
}
