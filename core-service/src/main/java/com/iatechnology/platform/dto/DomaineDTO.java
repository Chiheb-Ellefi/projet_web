package com.iatechnology.platform.dto;

import lombok.*;

import java.time.LocalDate;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DomaineDTO {

    private Long id;
    private String nom;
    private String description;
    private LocalDate dateCreation;
}
