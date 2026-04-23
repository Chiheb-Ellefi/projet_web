package com.iatechnology.platform.controller;

import com.iatechnology.platform.dto.*;
import com.iatechnology.platform.entity.ERole;
import com.iatechnology.platform.entity.Role;
import com.iatechnology.platform.entity.User;
import com.iatechnology.platform.repository.RoleRepository;
import com.iatechnology.platform.repository.UserRepository;
import com.iatechnology.platform.security.UserDetailsImpl;
import com.iatechnology.platform.security.jwt.JwtUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Contrôleur d'authentification.
 * - POST /api/auth/signin  → connexion, retourne JwtResponse
 * - POST /api/auth/signup  → inscription, retourne MessageResponse
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;

    // ─── CONNEXION ──────────────────────────────────────────────────────────

    /**
     * Authentifie l'utilisateur et retourne un token JWT.
     */
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()));
        } catch (org.springframework.security.core.AuthenticationException e) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Erreur d'authentification : " + e.getMessage()));
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return ResponseEntity.ok(JwtResponse.builder()
                .token(jwt)
                .id(userDetails.getId())
                .username(userDetails.getUsername())
                .email(userDetails.getEmail())
                .roles(roles)
                .build());
    }

    // ─── INSCRIPTION ────────────────────────────────────────────────────────

    /**
     * Enregistre un nouvel utilisateur.
     * Rôle par défaut : ROLE_USER sauf si spécifié dans le corps de la requête.
     */
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest signUpRequest) {

        // Vérifications d'unicité
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Erreur : ce nom d'utilisateur est déjà pris !"));
        }
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Erreur : cet email est déjà utilisé !"));
        }

        // Création de l'utilisateur avec mot de passe haché
        User user = User.builder()
                .username(signUpRequest.getUsername())
                .email(signUpRequest.getEmail())
                .password(encoder.encode(signUpRequest.getPassword()))
                .nom(signUpRequest.getNom())
                .prenom(signUpRequest.getPrenom())
                .enabled(true)
                .build();

        // Attribution des rôles
        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null || strRoles.isEmpty()) {
            // Rôle par défaut : ROLE_USER
            roles.add(findRole(ERole.ROLE_USER));
        } else {
            strRoles.forEach(role -> {
                switch (role.toLowerCase()) {
                    case "admin"                -> roles.add(findRole(ERole.ROLE_ADMIN));
                    case "mod", "moderateur"    -> roles.add(findRole(ERole.ROLE_MODERATEUR));
                    default                     -> roles.add(findRole(ERole.ROLE_USER));
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("Utilisateur enregistré avec succès !"));
    }

    // ─── HELPERS ────────────────────────────────────────────────────────────

    private Role findRole(ERole eRole) {
        return roleRepository.findByName(eRole)
                .orElseThrow(() -> new RuntimeException(
                        "Erreur : rôle introuvable — " + eRole.name()));
    }
}
