package com.iatechnology.platform.controller;

import com.iatechnology.platform.dto.DomaineDTO;
import com.iatechnology.platform.entity.Domaine;
import com.iatechnology.platform.service.DomaineService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller REST pour la gestion des domaines de recherche.
 *
 * Accès public   : GET  /api/public/domaines/**
 * Accès ADMIN    : POST/PUT/DELETE  /api/admin/domaines/**
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class DomaineController {

    private final DomaineService domaineService;

    // ─── PUBLIC ─────────────────────────────────────────────────────────────

    @GetMapping("/public/domaines")
    public ResponseEntity<List<Domaine>> getAll() {
        return ResponseEntity.ok(domaineService.getAllDomaines());
    }

    @GetMapping("/public/domaines/{id}")
    public ResponseEntity<Domaine> getById(@PathVariable("id") Long id) {
        return ResponseEntity.ok(domaineService.getDomaineById(id));
    }

    @GetMapping("/public/domaines/search")
    public ResponseEntity<List<Domaine>> searchByNom(@RequestParam String nom) {
        return ResponseEntity.ok(domaineService.searchByNom(nom));
    }

    // ─── ADMIN ──────────────────────────────────────────────────────────────

    @PostMapping("/admin/domaines")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Domaine> create(@Valid @RequestBody DomaineDTO dto) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(domaineService.createDomaine(dto));
    }

    @PutMapping("/admin/domaines/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Domaine> update(@PathVariable("id") Long id,
                                           @Valid @RequestBody DomaineDTO dto) {
        return ResponseEntity.ok(domaineService.updateDomaine(id, dto));
    }

    @DeleteMapping("/admin/domaines/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable("id") Long id) {
        domaineService.deleteDomaine(id);
        return ResponseEntity.noContent().build();
    }
}
