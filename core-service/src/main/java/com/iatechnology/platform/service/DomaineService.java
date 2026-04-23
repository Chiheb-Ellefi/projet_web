package com.iatechnology.platform.service;

import com.iatechnology.platform.dto.DomaineDTO;
import com.iatechnology.platform.entity.Domaine;
import com.iatechnology.platform.repository.DomaineRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class DomaineService {

    private final DomaineRepository domaineRepository;

    // ─── READ ───────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public List<Domaine> getAllDomaines() {
        return domaineRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Domaine getDomaineById(Long id) {
        return domaineRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Domaine not found with id: " + id));
    }

    // ─── CREATE ─────────────────────────────────────────────────────────────

    public Domaine createDomaine(DomaineDTO dto) {
        Domaine domaine = mapDtoToEntity(dto, new Domaine());
        return domaineRepository.save(domaine);
    }

    // ─── UPDATE ─────────────────────────────────────────────────────────────

    public Domaine updateDomaine(Long id, DomaineDTO dto) {
        Domaine existing = getDomaineById(id);
        mapDtoToEntity(dto, existing);
        return domaineRepository.save(existing);
    }

    // ─── DELETE ─────────────────────────────────────────────────────────────

    public void deleteDomaine(Long id) {
        Domaine domaine = getDomaineById(id);
        domaineRepository.delete(domaine);
    }

    // ─── SEARCH ─────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public List<Domaine> searchByNom(String nom) {
        return domaineRepository.findByNomContainingIgnoreCase(nom);
    }

    // ─── MAPPER ─────────────────────────────────────────────────────────────

    private Domaine mapDtoToEntity(DomaineDTO dto, Domaine domaine) {
        domaine.setNom(dto.getNom());
        domaine.setDescription(dto.getDescription());
        domaine.setDateCreation(dto.getDateCreation());
        return domaine;
    }
}
