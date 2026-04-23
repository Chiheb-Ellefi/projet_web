package com.iatechnology.platform.service;

import com.iatechnology.platform.dto.ProjetMisEnAvantDTO;
import com.iatechnology.platform.entity.ProjetMisEnAvant;
import com.iatechnology.platform.repository.ProjetMisEnAvantRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ProjetMisEnAvantService {

    private final ProjetMisEnAvantRepository projetRepository;

    public List<ProjetMisEnAvantDTO> getActifs() {
        return projetRepository.findByActifTrueOrderByOrdreAsc()
                .stream().map(this::mapToDTO).collect(Collectors.toList());
    }

    public List<ProjetMisEnAvantDTO> getAll() {
        return projetRepository.findAll()
                .stream().map(this::mapToDTO).collect(Collectors.toList());
    }

    public ProjetMisEnAvantDTO create(ProjetMisEnAvantDTO dto, String ajoutePar) {
        ProjetMisEnAvant p = ProjetMisEnAvant.builder()
                .titre(dto.getTitre())
                .description(dto.getDescription())
                .lienPublication(dto.getLienPublication())
                .imageUrl(dto.getImageUrl())
                .ordre(dto.getOrdre() != null ? dto.getOrdre() : 0)
                .actif(dto.getActif() != null ? dto.getActif() : true)
                .ajoutePar(ajoutePar)
                .build();
        return mapToDTO(projetRepository.save(p));
    }

    public ProjetMisEnAvantDTO update(Long id, ProjetMisEnAvantDTO dto) {
        ProjetMisEnAvant p = projetRepository.findById(id).orElseThrow(() -> new RuntimeException("Projet not found"));
        p.setTitre(dto.getTitre());
        p.setDescription(dto.getDescription());
        p.setLienPublication(dto.getLienPublication());
        p.setImageUrl(dto.getImageUrl());
        if(dto.getOrdre() != null) p.setOrdre(dto.getOrdre());
        if(dto.getActif() != null) p.setActif(dto.getActif());
        return mapToDTO(projetRepository.save(p));
    }

    public void delete(Long id) {
        projetRepository.deleteById(id);
    }

    public void changerOrdre(Long id, Integer nouvelOrdre) {
        ProjetMisEnAvant p = projetRepository.findById(id).orElseThrow(() -> new RuntimeException("Projet not found"));
        p.setOrdre(nouvelOrdre);
        projetRepository.save(p);
    }

    private ProjetMisEnAvantDTO mapToDTO(ProjetMisEnAvant p) {
        return ProjetMisEnAvantDTO.builder()
                .id(p.getId())
                .titre(p.getTitre())
                .description(p.getDescription())
                .lienPublication(p.getLienPublication())
                .imageUrl(p.getImageUrl())
                .ordre(p.getOrdre())
                .actif(p.getActif())
                .build();
    }
}
