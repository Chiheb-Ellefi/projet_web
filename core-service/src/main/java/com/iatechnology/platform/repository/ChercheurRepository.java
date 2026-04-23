package com.iatechnology.platform.repository;

import com.iatechnology.platform.entity.Chercheur;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ChercheurRepository extends JpaRepository<Chercheur, Long> {

    List<Chercheur> findByNomContainingIgnoreCase(String nom);

    List<Chercheur> findByDomainesId(Long domaineId);

    List<Chercheur> findBySpecialiteContainingIgnoreCase(String specialite);
}
