package com.security.jwttoken.security;

import com.security.jwttoken.service.JwtService;
import com.security.jwttoken.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    //JWTAutFilter ın görevi gelen request içerisindeki token i validate edecek.

    private final JwtService jwtService;
    private final UserService userService;


    public JwtAuthFilter(JwtService jwtService, UserService userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String autHeater = request.getHeader("Authorization");
        String token = null;
        String userName = null;
        if(autHeater != null && autHeater.startsWith("Bearer ")){
            token = autHeater.substring(7);
            userName = jwtService.extractUser(token);
        }
        if(userName != null && SecurityContextHolder.getContext().getAuthentication() ==null){
            UserDetails user = userService.loadUserByUsername(userName);
            if(jwtService.validateToken(token,user)){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(user,null,user.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request,response);
    }
}
