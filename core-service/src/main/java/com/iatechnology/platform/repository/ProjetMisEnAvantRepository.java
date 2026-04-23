package com.iatechnology.platform.repository;

import com.iatechnology.platform.entity.ProjetMisEnAvant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ProjetMisEnAvantRepository extends JpaRepository<ProjetMisEnAvant, Long> {
    List<ProjetMisEnAvant> findByActifTrueOrderByOrdreAsc();
}
