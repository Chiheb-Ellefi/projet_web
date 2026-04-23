package com.iatechnology.platform.repository;

import com.iatechnology.platform.entity.Domaine;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DomaineRepository extends JpaRepository<Domaine, Long> {

    List<Domaine> findByNomContainingIgnoreCase(String nom);
}
