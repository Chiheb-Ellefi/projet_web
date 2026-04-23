package delivery.system.gateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.util.Objects;


@Configuration
public class RateLimiterConfig {
    @Bean
    @Primary
    public KeyResolver ipKeyResolver() {
        return exchange -> {
            String ip= Objects.requireNonNull(exchange.getRequest().getRemoteAddress()).getAddress().getHostAddress();
            return Mono.just(ip);
        };
    }

    @Bean
    public KeyResolver userKeyResolver() {
        return exchange -> exchange.getPrincipal().map(Principal::getName).defaultIfEmpty("anonymous");
    }
    @Bean
    public KeyResolver apiKeyResolver(){
        return exchange -> {
            String apiKey=exchange.getRequest().getHeaders().getFirst("X-API-Key");
            return Mono.just(apiKey!=null?apiKey:"missing-api-key");
        };
    }

    @Bean
    KeyResolver deviceTokenKeyResolver() {
        return exchange -> {
            String deviceToken=exchange.getRequest().getHeaders().getFirst("X-Device-Token");
            return Mono.just(deviceToken!=null?deviceToken:"missing-device-token");
        };
    }
    @Bean
    public KeyResolver compositeKeyResolver(){
        return exchange -> {
            String ip= Objects.requireNonNull(exchange.getRequest().getRemoteAddress()).getAddress().getHostAddress();
            return exchange.getPrincipal().map(principal -> ip +":"+ principal.getName()).defaultIfEmpty("anonymous");
        };
    }
    @Bean
    @Primary
    public RedisRateLimiter standardRateLimiter() {
        return new RedisRateLimiter(10,20);
    }
    @Bean
    public RedisRateLimiter strictRateLimiter() {
        return new RedisRateLimiter(1,1);

    }
    @Bean
    public RedisRateLimiter generousRateLimiter() {
        return new RedisRateLimiter(100,200);
    }
    @Bean
    public RedisRateLimiter throttledRateLimiter() {
        return new RedisRateLimiter(1,60,60);
    }
    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("api_route_by_ip", r -> r
                        .path("/**")
                        .filters(f -> f
                                .requestRateLimiter(config -> config
                                        .setRateLimiter(generousRateLimiter())
                                        .setKeyResolver(ipKeyResolver())
                                        .setDenyEmptyKey(true)
                                        .setEmptyKeyStatus(HttpStatus.FORBIDDEN.name())
                                )
                        )
                        .uri("https://localhost:8080")
                )
                .build();
    }

}
