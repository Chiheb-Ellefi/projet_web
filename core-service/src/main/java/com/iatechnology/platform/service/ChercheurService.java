package com.iatechnology.platform.service;

import com.iatechnology.platform.dto.ChercheurDTO;
import com.iatechnology.platform.entity.Chercheur;
import com.iatechnology.platform.entity.Domaine;
import com.iatechnology.platform.repository.ChercheurRepository;
import com.iatechnology.platform.repository.DomaineRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Transactional
public class ChercheurService {

    private final ChercheurRepository chercheurRepository;
    private final DomaineRepository domaineRepository;

    // ─── READ ───────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public List<Chercheur> getAllChercheurs() {
        return chercheurRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Chercheur getChercheurById(Long id) {
        return chercheurRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Chercheur not found with id: " + id));
    }

    // ─── CREATE ─────────────────────────────────────────────────────────────

    public Chercheur createChercheur(ChercheurDTO dto) {
        Chercheur chercheur = mapDtoToEntity(dto, new Chercheur());
        return chercheurRepository.save(chercheur);
    }

    // ─── UPDATE ─────────────────────────────────────────────────────────────

    public Chercheur updateChercheur(Long id, ChercheurDTO dto) {
        Chercheur existing = getChercheurById(id);
        mapDtoToEntity(dto, existing);
        return chercheurRepository.save(existing);
    }

    // ─── DELETE ─────────────────────────────────────────────────────────────

    public void deleteChercheur(Long id) {
        Chercheur chercheur = getChercheurById(id);
        // Détacher des publications pour éviter les contraintes FK
        chercheur.getPublications().forEach(p -> p.getChercheurs().remove(chercheur));
        chercheurRepository.delete(chercheur);
    }

    // ─── SEARCH ─────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public List<Chercheur> searchByNom(String nom) {
        return chercheurRepository.findByNomContainingIgnoreCase(nom);
    }

    @Transactional(readOnly = true)
    public List<Chercheur> searchByDomaine(Long domaineId) {
        return chercheurRepository.findByDomainesId(domaineId);
    }

    @Transactional(readOnly = true)
    public List<Chercheur> searchBySpecialite(String specialite) {
        return chercheurRepository.findBySpecialiteContainingIgnoreCase(specialite);
    }

    // ─── MAPPER ─────────────────────────────────────────────────────────────

    private Chercheur mapDtoToEntity(ChercheurDTO dto, Chercheur chercheur) {
        chercheur.setNom(dto.getNom());
        chercheur.setPrenom(dto.getPrenom());
        chercheur.setEmail(dto.getEmail());
        chercheur.setTelephone(dto.getTelephone());
        chercheur.setSpecialite(dto.getSpecialite());
        chercheur.setPhoto(dto.getPhoto());
        chercheur.setDateNaissance(dto.getDateNaissance());
        chercheur.setBiographie(dto.getBiographie());

        // Résolution des domaines par IDs
        if (dto.getDomaineIds() != null && !dto.getDomaineIds().isEmpty()) {
            Set<Domaine> domaines = new HashSet<>(domaineRepository.findAllById(dto.getDomaineIds()));
            chercheur.setDomaines(domaines);
        }
        return chercheur;
    }
}
