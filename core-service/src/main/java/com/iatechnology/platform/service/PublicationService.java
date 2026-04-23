package com.iatechnology.platform.service;

import com.iatechnology.platform.dto.PublicationDTO;
import com.iatechnology.platform.entity.Chercheur;
import com.iatechnology.platform.entity.Domaine;
import com.iatechnology.platform.entity.Publication;
import com.iatechnology.platform.entity.Publication.TypePublication;
import com.iatechnology.platform.repository.ChercheurRepository;
import com.iatechnology.platform.repository.DomaineRepository;
import com.iatechnology.platform.repository.PublicationRepository;
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
public class PublicationService {

    private final PublicationRepository publicationRepository;
    private final DomaineRepository domaineRepository;
    private final ChercheurRepository chercheurRepository;

    // ─── READ ───────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public List<Publication> getAllPublications() {
        return publicationRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Publication getPublicationById(Long id) {
        return publicationRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Publication not found with id: " + id));
    }

    // ─── CREATE ─────────────────────────────────────────────────────────────

    public Publication createPublication(PublicationDTO dto) {
        Publication publication = mapDtoToEntity(dto, new Publication());
        return publicationRepository.save(publication);
    }

    // ─── UPDATE ─────────────────────────────────────────────────────────────

    public Publication updatePublication(Long id, PublicationDTO dto) {
        Publication existing = getPublicationById(id);
        mapDtoToEntity(dto, existing);
        return publicationRepository.save(existing);
    }

    // ─── DELETE ─────────────────────────────────────────────────────────────

    public void deletePublication(Long id) {
        Publication publication = getPublicationById(id);
        publicationRepository.delete(publication);
    }

    // ─── SEARCH ─────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public List<Publication> searchByMotCle(String motCle) {
        return publicationRepository.findByMotsClesContainingIgnoreCase(motCle);
    }

    @Transactional(readOnly = true)
    public List<Publication> searchByTitre(String titre) {
        return publicationRepository.findByTitreContainingIgnoreCase(titre);
    }

    @Transactional(readOnly = true)
    public List<Publication> getByDomaine(Long domaineId) {
        return publicationRepository.findByDomaineId(domaineId);
    }

    @Transactional(readOnly = true)
    public List<Publication> getByChercheur(Long chercheurId) {
        return publicationRepository.findByChercheurs_Id(chercheurId);
    }

    @Transactional(readOnly = true)
    public List<Publication> getByType(TypePublication type) {
        return publicationRepository.findByType(type);
    }

    // ─── MAPPER ─────────────────────────────────────────────────────────────

    private Publication mapDtoToEntity(PublicationDTO dto, Publication publication) {
        publication.setTitre(dto.getTitre());
        publication.setResume(dto.getResume());
        publication.setDatePublication(dto.getDatePublication());
        publication.setType(dto.getType());
        publication.setDoi(dto.getDoi());
        publication.setFichierUrl(dto.getFichierUrl());
        publication.setMotsCles(dto.getMotsCles());

        // Résolution du domaine
        if (dto.getDomaineId() != null) {
            Domaine domaine = domaineRepository.findById(dto.getDomaineId())
                    .orElseThrow(() -> new EntityNotFoundException("Domaine not found with id: " + dto.getDomaineId()));
            publication.setDomaine(domaine);
        }

        // Résolution des chercheurs
        if (dto.getChercheurIds() != null && !dto.getChercheurIds().isEmpty()) {
            Set<Chercheur> chercheurs = new HashSet<>(chercheurRepository.findAllById(dto.getChercheurIds()));
            publication.setChercheurs(chercheurs);
        }
        return publication;
    }
}
