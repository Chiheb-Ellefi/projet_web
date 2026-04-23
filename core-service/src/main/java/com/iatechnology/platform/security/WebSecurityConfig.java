package com.iatechnology.platform.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Configuration principale Spring Security.
 * JWT stateless — aucune session HTTP côté serveur.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final AuthEntryPointJwt unauthorizedHandler;
    private final AuthTokenFilter authTokenFilter;

    // ─── SECURITY FILTER CHAIN ──────────────────────────────────────────────

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Désactiver CSRF (API REST stateless)
            .csrf(AbstractHttpConfigurer::disable)

            // Gestionnaire d'erreur 401 personnalisé
            .exceptionHandling(ex ->
                    ex.authenticationEntryPoint(unauthorizedHandler))

            // Session STATELESS — aucun état serveur
            .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // ─── Règles d'autorisation ───────────────────────────────────────
            .authorizeHttpRequests(auth -> auth

                // Authentification — accès public
                .requestMatchers("/api/auth/**").permitAll()

                // Ressources publiques — accès public
                .requestMatchers("/api/public/**", "/api/files/download/**").permitAll()

                // Swagger / OpenAPI — accès public
                .requestMatchers(
                    "/v3/api-docs/**",
                    "/api/v3/api-docs/**",
                    "/api/auth/v3/api-docs/**",
                    "/swagger-ui/**",
                    "/swagger-ui.html",
                    "/error"
                ).permitAll()

                // Zone Admin — ADMIN uniquement
                .requestMatchers("/api/admin/**").hasRole("ADMIN")

                // Zone Modérateur — MODERATEUR ou ADMIN
                .requestMatchers("/api/moderateur/**").hasAnyRole("MODERATEUR", "ADMIN")

                // Zone Utilisateur — USER, MODERATEUR ou ADMIN
                .requestMatchers("/api/user/**").hasAnyRole("USER", "MODERATEUR", "ADMIN")

                // Toute autre requête nécessite une authentification
                .anyRequest().authenticated()
            )



            // Ajouter le filtre JWT avant UsernamePasswordAuthenticationFilter
            .addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
