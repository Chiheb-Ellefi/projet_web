package com.iatechnology.platform.service;

import com.iatechnology.platform.dto.UserDTO;
import com.iatechnology.platform.entity.ERole;
import com.iatechnology.platform.entity.Role;
import com.iatechnology.platform.entity.User;
import com.iatechnology.platform.repository.RoleRepository;
import com.iatechnology.platform.repository.UserRepository;
import com.iatechnology.platform.security.UserDetailsImpl;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    // ─── PROFIL ─────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public UserDTO getCurrentUserProfile() {
        UserDetailsImpl principal =
                (UserDetailsImpl) SecurityContextHolder.getContext()
                        .getAuthentication().getPrincipal();
        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur introuvable"));
        return toDTO(user);
    }

    public UserDTO updateCurrentUserProfile(UserDTO dto) {
        UserDetailsImpl principal =
                (UserDetailsImpl) SecurityContextHolder.getContext()
                        .getAuthentication().getPrincipal();
        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur introuvable"));

        user.setNom(dto.getNom());
        user.setPrenom(dto.getPrenom());
        return toDTO(userRepository.save(user));
    }

    // ─── ADMIN ──────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public List<UserDTO> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::toDTO)
                .collect(Collectors.toList());
    }

    public UserDTO updateUserRole(Long userId, String roleName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur introuvable : " + userId));

        ERole eRole;
        try {
            eRole = ERole.valueOf(roleName.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Rôle invalide : " + roleName);
        }

        Role role = roleRepository.findByName(eRole)
                .orElseThrow(() -> new EntityNotFoundException("Rôle introuvable : " + roleName));

        user.setRoles(Set.of(role));
        return toDTO(userRepository.save(user));
    }

    public void deleteUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur introuvable : " + userId));
        userRepository.delete(user);
    }

    // ─── MAPPER ─────────────────────────────────────────────────────────────

    private UserDTO toDTO(User user) {
        return UserDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .nom(user.getNom())
                .prenom(user.getPrenom())
                .enabled(user.isEnabled())
                .build();
    }
}
