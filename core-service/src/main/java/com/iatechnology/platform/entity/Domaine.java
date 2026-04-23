package com.iatechnology.platform.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Entité représentant un domaine de recherche scientifique.
 */
@Entity
@Table(name = "domaines")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Domaine {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(nullable = false, unique = true, length = 150)
    private String nom;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "date_creation")
    private LocalDate dateCreation;

    /**
     * Relation ManyToMany inverse avec les chercheurs.
     */
    @ManyToMany(mappedBy = "domaines", fetch = FetchType.LAZY)
    @Builder.Default
    @JsonIgnoreProperties({"domaines", "publications"})
    private Set<Chercheur> chercheurs = new HashSet<>();

    /**
     * Relation OneToMany inverse avec les publications.
     */
    @OneToMany(mappedBy = "domaine", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @Builder.Default
    @JsonIgnoreProperties({"domaine", "chercheurs"})
    private Set<Publication> publications = new HashSet<>();
}
