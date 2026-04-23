package delivery.system.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Flux;

import java.util.Collection;
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

                        .pathMatchers("/api/public/**").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/files/download/**").permitAll()


                        .pathMatchers(HttpMethod.POST, "/api/files/upload")
                        .hasAnyRole("ADMIN", "MODERATEUR")


                        .pathMatchers("/api/moderateur/**")
                        .hasAnyRole("MODERATEUR", "ADMIN")


                        .pathMatchers("/api/user/**")
                        .hasAnyRole("USER", "MODERATEUR", "ADMIN")


                        .pathMatchers("/api/admin/**")
                        .hasRole("ADMIN")


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