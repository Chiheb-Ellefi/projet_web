package com.iatechnology.platform.repository;

import com.iatechnology.platform.entity.Publication;
import com.iatechnology.platform.entity.Publication.TypePublication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PublicationRepository extends JpaRepository<Publication, Long> {

    List<Publication> findByTitreContainingIgnoreCase(String titre);

    List<Publication> findByMotsClesContainingIgnoreCase(String motCle);

    List<Publication> findByType(TypePublication type);

    List<Publication> findByDomaineId(Long domaineId);

    List<Publication> findByChercheurs_Id(Long chercheurId);
}
