package com.iatechnology.platform.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;

/**
 * Utilitaire JWT dans le sous-package security/jwt/.
 * Génération, validation et extraction du token Bearer.
 */
@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${iatechnology.app.jwtSecret}")
    private String jwtSecret;

    @Value("${iatechnology.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    // ─── CLEF DE SIGNATURE ──────────────────────────────────────────────────

    private Key key() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    // ─── EXTRACTION ─────────────────────────────────────────────────────────

    /**
     * Extrait le nom d'utilisateur (subject) du token JWT.
     */
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> getRolesFromJwtToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("roles", List.class);
    }

    // ─── VALIDATION ─────────────────────────────────────────────────────────

    /**
     * Valide le token JWT et retourne true si valide, false sinon.
     */
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Token JWT invalide : {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("Token JWT expiré : {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("Type de token JWT non supporté : {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string est vide : {}", e.getMessage());
        }
        return false;
    }
}
