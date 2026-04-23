package com.iatechnology.platform.repository;

import com.iatechnology.platform.entity.Actualite;
import com.iatechnology.platform.entity.CategorieActualite;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ActualiteRepository extends JpaRepository<Actualite, Long> {
    List<Actualite> findByVisibleTrueOrderByDatePublicationDesc();
    List<Actualite> findByCategorie(CategorieActualite categorie);
    List<Actualite> findByEstEpingleTrueAndVisibleTrue();
}
