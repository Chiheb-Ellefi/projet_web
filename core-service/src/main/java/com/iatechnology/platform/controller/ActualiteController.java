package com.iatechnology.platform.controller;

import com.iatechnology.platform.dto.ActualiteCreateRequest;
import com.iatechnology.platform.dto.ActualiteDTO;
import com.iatechnology.platform.entity.CategorieActualite;
import com.iatechnology.platform.service.ActualiteService;
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
public class ActualiteController {

    private final ActualiteService actualiteService;

    // PUBLICS
    @GetMapping("/public/actualites")
    public ResponseEntity<List<ActualiteDTO>> getAllVisible() {
        return ResponseEntity.ok(actualiteService.getAllVisible());
    }

    @GetMapping("/public/actualites/{id}")
    public ResponseEntity<ActualiteDTO> getById(@PathVariable("id") Long id) {
        return ResponseEntity.ok(actualiteService.getById(id));
    }

    @GetMapping("/public/actualites/epingles")
    public ResponseEntity<List<ActualiteDTO>> getEpingles() {
        return ResponseEntity.ok(actualiteService.getEpingles());
    }

    @GetMapping("/public/actualites/categorie/{cat}")
    public ResponseEntity<List<ActualiteDTO>> getByCategorie(@PathVariable("cat") CategorieActualite cat) {
        return ResponseEntity.ok(actualiteService.getByCategorie(cat));
    }

    // MODERATEUR
    @GetMapping("/moderateur/actualites")
    @PreAuthorize("hasAnyRole('MODERATEUR', 'ADMIN')")
    public ResponseEntity<List<ActualiteDTO>> getAll() {
        return ResponseEntity.ok(actualiteService.getAll());
    }

    @PostMapping("/moderateur/actualites")
    @PreAuthorize("hasAnyRole('MODERATEUR', 'ADMIN')")
    public ResponseEntity<ActualiteDTO> create(@RequestBody ActualiteCreateRequest req) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return ResponseEntity.status(HttpStatus.CREATED).body(actualiteService.create(req, username));
    }

    @PutMapping("/moderateur/actualites/{id}")
    @PreAuthorize("hasAnyRole('MODERATEUR', 'ADMIN')")
    public ResponseEntity<ActualiteDTO> update(@PathVariable("id") Long id, @RequestBody ActualiteCreateRequest req) {
        return ResponseEntity.ok(actualiteService.update(id, req));
    }

    @DeleteMapping("/moderateur/actualites/{id}")
    @PreAuthorize("hasAnyRole('MODERATEUR', 'ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable("id") Long id) {
        actualiteService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/moderateur/actualites/{id}/visibilite")
    @PreAuthorize("hasAnyRole('MODERATEUR', 'ADMIN')")
    public ResponseEntity<Void> toggleVisibilite(@PathVariable Long id) {
        actualiteService.toggleVisibilite(id);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/moderateur/actualites/{id}/epingle")
    @PreAuthorize("hasAnyRole('MODERATEUR', 'ADMIN')")
    public ResponseEntity<Void> toggleEpingle(@PathVariable("id") Long id) {
        actualiteService.toggleEpingle(id);
        return ResponseEntity.noContent().build();
    }
}