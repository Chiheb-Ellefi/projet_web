package com.iatechnology.platform.service;

import com.iatechnology.platform.dto.ActualiteCreateRequest;
import com.iatechnology.platform.dto.ActualiteDTO;
import com.iatechnology.platform.entity.Actualite;
import com.iatechnology.platform.entity.CategorieActualite;
import com.iatechnology.platform.repository.ActualiteRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ActualiteService {

    private final ActualiteRepository actualiteRepository;

    public List<ActualiteDTO> getAllVisible() {
        return actualiteRepository.findByVisibleTrueOrderByDatePublicationDesc()
                .stream().map(this::mapToDTO).collect(Collectors.toList());
    }

    public List<ActualiteDTO> getAll() {
        return actualiteRepository.findAll()
                .stream().map(this::mapToDTO).collect(Collectors.toList());
    }

    public ActualiteDTO getById(Long id) {
        Actualite a = actualiteRepository.findById(id).orElseThrow(() -> new RuntimeException("Actualite not found"));
        return mapToDTO(a);
    }

    public List<ActualiteDTO> getEpingles() {
        return actualiteRepository.findByEstEpingleTrueAndVisibleTrue()
                .stream().map(this::mapToDTO).collect(Collectors.toList());
    }

    public List<ActualiteDTO> getByCategorie(CategorieActualite cat) {
        return actualiteRepository.findByCategorie(cat)
                .stream().map(this::mapToDTO).collect(Collectors.toList());
    }

    public ActualiteDTO create(ActualiteCreateRequest req, String auteur) {
        Actualite a = Actualite.builder()
                .titre(req.getTitre())
                .contenu(req.getContenu())
                .imageUrl(req.getImageUrl())
                .estEpingle(req.getEstEpingle() != null ? req.getEstEpingle() : false)
                .categorie(req.getCategorie())
                .auteur(auteur)
                .visible(true)
                .build();
        return mapToDTO(actualiteRepository.save(a));
    }

    public ActualiteDTO update(Long id, ActualiteCreateRequest req) {
        Actualite a = actualiteRepository.findById(id).orElseThrow(() -> new RuntimeException("Actualite not found"));
        a.setTitre(req.getTitre());
        a.setContenu(req.getContenu());
        a.setImageUrl(req.getImageUrl());
        if (req.getEstEpingle() != null) a.setEstEpingle(req.getEstEpingle());
        a.setCategorie(req.getCategorie());
        return mapToDTO(actualiteRepository.save(a));
    }

    public void delete(Long id) {
        actualiteRepository.deleteById(id);
    }

    public void toggleVisibilite(Long id) {
        Actualite a = actualiteRepository.findById(id).orElseThrow(() -> new RuntimeException("Actualite not found"));
        a.setVisible(a.getVisible() == null || !a.getVisible());
        actualiteRepository.save(a);
    }

    public void toggleEpingle(Long id) {
        Actualite a = actualiteRepository.findById(id).orElseThrow(() -> new RuntimeException("Actualite not found"));
        a.setEstEpingle(a.getEstEpingle() == null || !a.getEstEpingle());
        actualiteRepository.save(a);
    }

    private ActualiteDTO mapToDTO(Actualite a) {
        return ActualiteDTO.builder()
                .id(a.getId())
                .titre(a.getTitre())
                .contenu(a.getContenu())
                .datePublication(a.getDatePublication())
                .auteur(a.getAuteur())
                .imageUrl(a.getImageUrl())
                .estEpingle(a.getEstEpingle())
                .categorie(a.getCategorie())
                .visible(a.getVisible())
                .build();
    }
}
