package com.iatechnology.platform.controller;

import com.iatechnology.platform.dto.PublicationDTO;
import com.iatechnology.platform.entity.Publication;
import com.iatechnology.platform.entity.Publication.TypePublication;
import com.iatechnology.platform.service.PublicationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class PublicationController {

    private final PublicationService publicationService;

    // ─── PUBLIC ─────────────────────────────────────────────────────────────

    @GetMapping("/public/publications")
    public ResponseEntity<List<Publication>> getAll() {
        return ResponseEntity.ok(publicationService.getAllPublications());
    }

    @GetMapping("/public/publications/{id}")
    public ResponseEntity<Publication> getById(@PathVariable("id") Long id) {
        return ResponseEntity.ok(publicationService.getPublicationById(id));
    }

    @GetMapping("/public/publications/search")
    public ResponseEntity<List<Publication>> searchByMotCle(@RequestParam String motCle) {
        return ResponseEntity.ok(publicationService.searchByMotCle(motCle));
    }

    @GetMapping("/public/publications/titre")
    public ResponseEntity<List<Publication>> searchByTitre(@RequestParam String titre) {
        return ResponseEntity.ok(publicationService.searchByTitre(titre));
    }

    @GetMapping("/public/publications/type/{type}")
    public ResponseEntity<List<Publication>> getByType(@PathVariable("type") TypePublication type) {
        return ResponseEntity.ok(publicationService.getByType(type));
    }

    @GetMapping("/public/publications/domaine/{domaineId}")
    public ResponseEntity<List<Publication>> getByDomaine(@PathVariable("domaineId") Long domaineId) {
        return ResponseEntity.ok(publicationService.getByDomaine(domaineId));
    }

    // ─── USER + ─────────────────────────────────────────────────────────────

    @GetMapping("/user/publications/chercheur/{chercheurId}")
    @PreAuthorize("hasAnyRole('USER', 'MODERATEUR', 'ADMIN')")
    public ResponseEntity<List<Publication>> getByChercheur(@PathVariable("chercheurId") Long chercheurId) {
        return ResponseEntity.ok(publicationService.getByChercheur(chercheurId));
    }

    // ─── ADMIN ──────────────────────────────────────────────────────────────

    @PostMapping("/admin/publications")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Publication> create(@Valid @RequestBody PublicationDTO dto) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(publicationService.createPublication(dto));
    }

    @PutMapping("/admin/publications/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Publication> update(@PathVariable("id") Long id,
                                              @Valid @RequestBody PublicationDTO dto) {
        return ResponseEntity.ok(publicationService.updatePublication(id, dto));
    }

    @DeleteMapping("/admin/publications/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable("id") Long id) {
        publicationService.deletePublication(id);
        return ResponseEntity.noContent().build();
    }
}