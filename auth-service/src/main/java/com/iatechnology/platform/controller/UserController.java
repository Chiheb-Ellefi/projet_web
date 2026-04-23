package com.iatechnology.platform.controller;

import com.iatechnology.platform.dto.UserDTO;
import com.iatechnology.platform.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller REST pour la gestion des utilisateurs.
 *
 * Accès USER+  : GET/PUT  /api/user/profile
 * Accès ADMIN  : GET/PUT/DELETE  /api/admin/users/**
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    // ─── PROFIL UTILISATEUR ──────────────────────────────────────────────────

    @GetMapping("/user/profile")
    @PreAuthorize("hasAnyRole('USER', 'MODERATEUR', 'ADMIN')")
    public ResponseEntity<UserDTO> getCurrentUser() {
        return ResponseEntity.ok(userService.getCurrentUserProfile());
    }

    @PutMapping("/user/profile")
    @PreAuthorize("hasAnyRole('USER', 'MODERATEUR', 'ADMIN')")
    public ResponseEntity<UserDTO> updateProfile(@RequestBody UserDTO dto) {
        return ResponseEntity.ok(userService.updateCurrentUserProfile(dto));
    }

    // ─── ADMIN ──────────────────────────────────────────────────────────────

    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserDTO>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @PutMapping("/admin/users/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDTO> updateUserRole(@PathVariable("id") Long id,
                                                   @RequestParam String role) {
        return ResponseEntity.ok(userService.updateUserRole(id, role));
    }

    @DeleteMapping("/admin/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable("id") Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
