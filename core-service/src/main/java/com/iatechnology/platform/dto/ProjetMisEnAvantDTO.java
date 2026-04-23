package com.iatechnology.platform.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ProjetMisEnAvantDTO {
    private Long id;
    private String titre;
    private String description;
    private Long lienPublication;
    private String imageUrl;
    private Integer ordre;
    private Boolean actif;
}
