package com.iatechnology.platform.dto;

import com.iatechnology.platform.entity.CategorieActualite;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ActualiteCreateRequest {
    private String titre;
    private String contenu;
    private String imageUrl;
    private Boolean estEpingle;
    private CategorieActualite categorie;
}
