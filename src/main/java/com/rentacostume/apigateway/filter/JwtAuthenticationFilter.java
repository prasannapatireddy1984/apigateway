package com.rentacostume.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.List;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret}")
    private String jwtSecret;

    private static final List<String> PUBLIC_PATHS = List.of(
            "/api/users/login",
            "/api/users/register",
            "/api/vendors/login",
            "/api/vendors/register",
            "/api/vendors/public",
            "/api/orders/public",
            "/api/catalog",
            "/api/reviews"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();

        if (isPublicPath(path) || "OPTIONS".equalsIgnoreCase(exchange.getRequest().getMethod().name())) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String roles = String.valueOf(claims.get("roles"));

            if (isAdminPath(path) && !roles.contains("ADMIN")) {
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }

            if (isVendorPath(path) && !roles.contains("VENDOR")) {
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }

            if (isUserPath(path) && !roles.contains("USER")) {
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }

            ServerWebExchange mutatedExchange = exchange.mutate()
                    .request(builder -> builder
                            .header("X-User-Id", claims.getSubject())
                            .header("X-User-Email", String.valueOf(claims.get("email")))
                            .header("X-User-Name", String.valueOf(claims.get("username")))
                            .header("X-User-Roles", String.valueOf(claims.get("roles")))
                    )
                    .build();

            return chain.filter(mutatedExchange);

        } catch (Exception e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(path::startsWith);
    }

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public int getOrder() {
        return -1;
    }

    private boolean isVendorPath(String path) {
        return !isAdminPath(path) && (
                path.startsWith("/api/vendor")
                        || path.startsWith("/api/vendors")
                        || path.startsWith("/api/orders/vendor")
        );
    }

    private boolean isUserPath(String path) {
        return path.startsWith("/api/cart")
                || (
                path.startsWith("/api/orders")
                        && !path.startsWith("/api/orders/vendor")
                        && !path.startsWith("/api/orders/admin")
        );
    }

    private boolean isAdminPath(String path) {
        return path.startsWith("/api/vendors/admin")
                || path.startsWith("/api/users/admin")
                || path.startsWith("/api/orders/admin")
                || path.startsWith("/api/catalog/admin")
                || path.startsWith("/api/admin");
    }
}