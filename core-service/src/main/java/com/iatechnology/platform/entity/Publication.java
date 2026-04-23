package com.iatechnology.platform.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Entité représentant une publication scientifique.
 */
@Entity
@Table(name = "publications")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Publication {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(nullable = false, length = 300)
    private String titre;

    @Column(columnDefinition = "TEXT")
    private String resume;

    @Column(name = "date_publication")
    private LocalDate datePublication;

    @Enumerated(EnumType.STRING)
    @Column(length = 20, nullable = false)
    private TypePublication type;

    @Column(length = 200)
    private String doi;

    @Column(name = "fichier_url", length = 500)
    private String fichierUrl;

    @Column(name = "mots_cles", length = 500)
    private String motsCles;

    /**
     * Relation ManyToOne vers le domaine de la publication.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "domaine_id")
    @JsonIgnoreProperties({"publications", "chercheurs"})
    private Domaine domaine;

    /**
     * Relation ManyToMany avec les chercheurs auteurs.
     * Table de jointure : publication_chercheur
     */
    @ManyToMany(fetch = FetchType.LAZY, cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    @JoinTable(name = "publication_chercheur",
               joinColumns = @JoinColumn(name = "publication_id"),
               inverseJoinColumns = @JoinColumn(name = "chercheur_id"))
    @Builder.Default
    @JsonIgnoreProperties({"publications", "domaines"})
    private Set<Chercheur> chercheurs = new HashSet<>();

    /**
     * Enum interne pour le type de publication.
     */
    public enum TypePublication {
        ARTICLE, THESE, RAPPORT, CONFERENCE
    }
}
