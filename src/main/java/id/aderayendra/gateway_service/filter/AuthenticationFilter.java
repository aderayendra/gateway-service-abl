package id.aderayendra.gateway_service.filter;

import id.aderayendra.gateway_service.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Objects;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private JwtUtils jwtUtils;

    private static final List<String> OPEN_API_ENDPOINTS = List.of(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/validate",
            "/eureka",
            "/actuator"
    );

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String path = exchange.getRequest().getURI().getPath();
            String method = exchange.getRequest().getMethod().name();

            // Allow public access to certain endpoints
            boolean isOpenApi = OPEN_API_ENDPOINTS.stream().anyMatch(path::contains);
            boolean isPublicProductGet = path.startsWith("/api/produk") && "GET".equalsIgnoreCase(method);

            if (isOpenApi || isPublicProductGet) {
                System.out.println("OPEN API");
                return chain.filter(exchange);
            }

            if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                System.out.println("Missing authorization header");
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing authorization header");
            }

            String authHeader = Objects.requireNonNull(exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION)).get(0);
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                authHeader = authHeader.substring(7);
                System.out.println("Got the token header" + authHeader);
            }

            if (!jwtUtils.validateToken(authHeader)) {
                System.out.println("Invalid access token");
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid access token");
            }

            // Inject user info into headers for downstream services
            String username = jwtUtils.extractUsername(authHeader);
            ServerHttpRequest request = exchange.getRequest().mutate()
                    .header("loggedInUser", username)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + authHeader)
                    .build();

            System.out.println("ALL Good, delegating the token");
            return chain.filter(exchange.mutate().request(request).build());
        };
    }

    public static class Config {
    }
}
