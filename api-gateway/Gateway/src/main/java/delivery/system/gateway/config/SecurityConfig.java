package delivery.system.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Flux;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges

                        // ─── Public ────────────────────────────────────────
                        .pathMatchers("/api/public/**").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/files/download/**").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/users/register").permitAll()  // ← ADD

                        // ─── File upload ────────────────────────────────────
                        .pathMatchers(HttpMethod.POST, "/api/files/upload")
                        .hasAnyRole("ADMIN", "MODERATEUR")

                        // ─── Moderateur ────────────────────────────────────
                        .pathMatchers("/api/moderateur/**")
                        .hasAnyRole("MODERATEUR", "ADMIN")

                        // ─── User ──────────────────────────────────────────
                        .pathMatchers("/api/user/**")
                        .hasAnyRole("USER", "MODERATEUR", "ADMIN")

                        // ─── Admin (research) ──────────────────────────────
                        .pathMatchers("/api/admin/**").hasRole("ADMIN")

                        // ─── Auth service management (admin only) ──────────  ← ADD BLOCK
                        .pathMatchers("/api/v1/users/**").hasRole("ADMIN")
                        .pathMatchers("/api/v1/roles/**").hasRole("ADMIN")
                        .pathMatchers("/api/v1/authorities/**").hasRole("ADMIN")
                        .pathMatchers("/api/v1/clients/**").hasRole("ADMIN")
                        .pathMatchers("/actuator/**").permitAll()

                        .pathMatchers("/api/public/**").permitAll()
                        .pathMatchers(
                                "/swagger-ui.html",
                                "/swagger-ui/**",
                                "/webjars/**",
                                "/v3/api-docs/**",
                                "/v3/api-docs.yaml",
                                "/core-service/v3/api-docs",   // ← ADD
                                "/core-service/v3/api-docs/**", // ← ADD
                                "/auth-service/v3/api-docs",    // ← ADD
                                "/auth-service/v3/api-docs/**"  // ← ADD
                        ).permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                )
                .build();
    }

    @Bean
    public ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<String> authorities = jwt.getClaimAsStringList("authorities");
            if (authorities == null) authorities = Collections.emptyList();

            return Flux.fromIterable(
                    authorities.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList())
            );
        });

        converter.setPrincipalClaimName("username");

        return converter;
    }
}