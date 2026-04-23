package com.iatechnology.platform;

import com.iatechnology.platform.entity.*;
import com.iatechnology.platform.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final ActualiteRepository actualiteRepository;
    private final ProjetMisEnAvantRepository projetRepository;

    @Override
    public void run(String... args) throws Exception {



        if (actualiteRepository.count() == 0) {
            actualiteRepository.save(Actualite.builder().titre("Nouveau partenariat NLP").categorie(CategorieActualite.ACTUALITE).estEpingle(true).visible(true).contenu("Détails concernant notre nouveau partenariat.").auteur("moderateur").build());
            actualiteRepository.save(Actualite.builder().titre("Conférence IA 2025").categorie(CategorieActualite.ANNONCE).estEpingle(false).visible(true).contenu("Nous animerons une grande conférence cette année.").auteur("moderateur").build());
            actualiteRepository.save(Actualite.builder().titre("Projet Vision IA lancé").categorie(CategorieActualite.PROJET_RECENT).estEpingle(true).visible(true).contenu("La version beta est officiellement en ligne.").auteur("admin").build());
        }

        if (projetRepository.count() == 0) {
            projetRepository.save(ProjetMisEnAvant.builder().titre("Détection d'objets temps réel").ordre(1).actif(true).description("Test").ajoutePar("admin").build());
            projetRepository.save(ProjetMisEnAvant.builder().titre("Analyse de sentiment NLP").ordre(2).actif(true).description("Test").ajoutePar("admin").build());
        }
    }
}
