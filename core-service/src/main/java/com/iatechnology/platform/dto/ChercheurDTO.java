package com.iatechnology.platform.dto;

import lombok.*;

import java.time.LocalDate;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ChercheurDTO {

    private Long id;
    private String nom;
    private String prenom;
    private String email;
    private String telephone;
    private String specialite;
    private String photo;
    private LocalDate dateNaissance;
    private String biographie;
    private Set<Long> domaineIds;
}
