package com.iatechnology.platform.controller;

import com.iatechnology.platform.dto.ProjetMisEnAvantDTO;
import com.iatechnology.platform.service.ProjetMisEnAvantService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ProjetMisEnAvantController {

    private final ProjetMisEnAvantService projetService;

    // PUBLICS
    @GetMapping("/public/projets-mis-en-avant")
    public ResponseEntity<List<ProjetMisEnAvantDTO>> getActifs() {
        return ResponseEntity.ok(projetService.getActifs());
    }

    // MODERATEUR
    @GetMapping("/moderateur/projets-mis-en-avant")
    @PreAuthorize("hasAnyRole('MODERATEUR', 'ADMIN')")
    public ResponseEntity<List<ProjetMisEnAvantDTO>> getAll() {
        return ResponseEntity.ok(projetService.getAll());
    }

    @PostMapping("/moderateur/projets-mis-en-avant")
    @PreAuthorize("hasAnyRole('MODERATEUR', 'ADMIN')")
    public ResponseEntity<ProjetMisEnAvantDTO> create(@RequestBody ProjetMisEnAvantDTO dto) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return ResponseEntity.status(HttpStatus.CREATED).body(projetService.create(dto, username));
    }

    @PutMapping("/moderateur/projets-mis-en-avant/{id}")
    @PreAuthorize("hasAnyRole('MODERATEUR', 'ADMIN')")
    public ResponseEntity<ProjetMisEnAvantDTO> update(@PathVariable("id") Long id, @RequestBody ProjetMisEnAvantDTO dto) {
        return ResponseEntity.ok(projetService.update(id, dto));
    }

    @DeleteMapping("/moderateur/projets-mis-en-avant/{id}")
    @PreAuthorize("hasAnyRole('MODERATEUR', 'ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable("id") Long id) {
        projetService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/moderateur/projets-mis-en-avant/{id}/ordre")
    @PreAuthorize("hasAnyRole('MODERATEUR', 'ADMIN')")
    public ResponseEntity<Void> changerOrdre(@PathVariable("id") Long id, @RequestParam("nouvelOrdre") Integer nouvelOrdre) {
        projetService.changerOrdre(id, nouvelOrdre);
        return ResponseEntity.noContent().build();
    }
}
