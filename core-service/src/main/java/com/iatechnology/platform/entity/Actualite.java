package com.iatechnology.platform.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import java.time.LocalDateTime;

@Entity
@Table(name = "actualites")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Actualite {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(nullable = false, length = 200)
    private String titre;

    @Column(columnDefinition = "TEXT")
    private String contenu;

    @CreationTimestamp
    @Column(name = "date_publication", updatable = false)
    private LocalDateTime datePublication;

    @UpdateTimestamp
    @Column(name = "date_modification")
    private LocalDateTime dateModification;

    @Column(length = 150)
    private String auteur; // username du modérateur

    @Column(name = "image_url", length = 500)
    private String imageUrl;

    @Column(name = "est_epingle")
    @Builder.Default
    private Boolean estEpingle = false;

    @Enumerated(EnumType.STRING)
    @Column(length = 50)
    private CategorieActualite categorie;

    @Column(nullable = false)
    @Builder.Default
    private Boolean visible = true;
}
