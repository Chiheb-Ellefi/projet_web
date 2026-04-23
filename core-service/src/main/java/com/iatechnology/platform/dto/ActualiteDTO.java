package com.iatechnology.platform.dto;

import com.iatechnology.platform.entity.CategorieActualite;
import lombok.*;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ActualiteDTO {
    private Long id;
    private String titre;
    private String contenu;
    private LocalDateTime datePublication;
    private String auteur;
    private String imageUrl;
    private Boolean estEpingle;
    private CategorieActualite categorie;
    private Boolean visible;
}
