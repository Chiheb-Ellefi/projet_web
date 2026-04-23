package com.iatechnology.platform.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Entité représentant un chercheur scientifique.
 */
@Entity
@Table(name = "chercheurs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Chercheur {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(nullable = false, length = 80)
    private String nom;

    @NotBlank
    @Column(nullable = false, length = 80)
    private String prenom;

    @NotBlank
    @Email
    @Column(nullable = false, unique = true, length = 120)
    private String email;

    @Column(length = 20)
    private String telephone;

    @Column(length = 150)
    private String specialite;

    @Column(length = 500)
    private String photo;

    @Column(name = "date_naissance")
    private LocalDate dateNaissance;

    @Column(columnDefinition = "TEXT")
    private String biographie;

    /**
     * Relation ManyToMany avec les domaines.
     * Table de jointure : chercheur_domaine
     */
    @ManyToMany(fetch = FetchType.LAZY, cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    @JoinTable(name = "chercheur_domaine",
               joinColumns = @JoinColumn(name = "chercheur_id"),
               inverseJoinColumns = @JoinColumn(name = "domaine_id"))
    @Builder.Default
    @JsonIgnoreProperties({"chercheurs", "publications"})
    private Set<Domaine> domaines = new HashSet<>();

    /**
     * Relation ManyToMany inverse avec les publications.
     */
    @ManyToMany(mappedBy = "chercheurs", fetch = FetchType.LAZY)
    @Builder.Default
    @JsonIgnoreProperties({"chercheurs", "domaine"})
    private Set<Publication> publications = new HashSet<>();
}
