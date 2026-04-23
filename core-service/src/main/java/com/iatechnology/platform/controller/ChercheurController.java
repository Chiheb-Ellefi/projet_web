package com.iatechnology.platform.controller;

import com.iatechnology.platform.dto.ChercheurDTO;
import com.iatechnology.platform.entity.Chercheur;
import com.iatechnology.platform.service.ChercheurService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller REST pour la gestion des chercheurs.
 *
 * Accès public   : GET  /api/public/chercheurs/**
 * Accès ADMIN    : POST/PUT/DELETE  /api/admin/chercheurs/**
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ChercheurController {

    private final ChercheurService chercheurService;

    // ─── PUBLIC ─────────────────────────────────────────────────────────────

    @GetMapping("/public/chercheurs")
    public ResponseEntity<List<Chercheur>> getAll() {
        return ResponseEntity.ok(chercheurService.getAllChercheurs());
    }

    @GetMapping("/public/chercheurs/{id}")
    public ResponseEntity<Chercheur> getById(@PathVariable("id") Long id) {
        return ResponseEntity.ok(chercheurService.getChercheurById(id));
    }

    @GetMapping("/public/chercheurs/search")
    public ResponseEntity<List<Chercheur>> searchByNom(@RequestParam String nom) {
        return ResponseEntity.ok(chercheurService.searchByNom(nom));
    }

    @GetMapping("/public/chercheurs/specialite")
    public ResponseEntity<List<Chercheur>> searchBySpecialite(@RequestParam String specialite) {
        return ResponseEntity.ok(chercheurService.searchBySpecialite(specialite));
    }

    @GetMapping("/public/chercheurs/domaine/{domaineId}")
    public ResponseEntity<List<Chercheur>> getByDomaine(@PathVariable("domaineId") Long domaineId) {
        return ResponseEntity.ok(chercheurService.searchByDomaine(domaineId));
    }

    // ─── ADMIN ──────────────────────────────────────────────────────────────

    @PostMapping("/admin/chercheurs")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Chercheur> create(@Valid @RequestBody ChercheurDTO dto) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(chercheurService.createChercheur(dto));
    }

    @PutMapping("/admin/chercheurs/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Chercheur> update(@PathVariable("id") Long id,
                                             @Valid @RequestBody ChercheurDTO dto) {
        return ResponseEntity.ok(chercheurService.updateChercheur(id, dto));
    }

    @DeleteMapping("/admin/chercheurs/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable("id") Long id) {
        chercheurService.deleteChercheur(id);
        return ResponseEntity.noContent().build();
    }
}
