package com.iatechnology.platform.dto;

import com.iatechnology.platform.entity.Publication.TypePublication;
import lombok.*;

import java.time.LocalDate;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PublicationDTO {

    private Long id;
    private String titre;
    private String resume;
    private LocalDate datePublication;
    private TypePublication type;
    private String doi;
    private String fichierUrl;
    private String motsCles;
    private Long domaineId;
    private String domaineNom;
    private Set<Long> chercheurIds;
}
