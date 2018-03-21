package com.intech.api;

import lombok.Data;

import javax.validation.constraints.NotNull;
import java.util.List;

@Data
public class SuperheroDto {

    private long idHero;

    @NotNull
    private String fullName;

    private String placeOfBirth;

    private String imageSrc;

    @NotNull
    private String heroName;
    
    private int intelligence;

    private int strength;

    private int speed;

    private int durability;

    private int power;

    private int combat;

    private String alterEgos;

    private String aliases;

    private String firstAppearance;

    private String publisher;

    private String alignment;

    private String gender;

    private String race;

    private String height;

    private String weight;

    private String eyes;

    private String hairs;

    private String occupation;

    private String base;

    private String relatives;

    private String history;

    private String powers;

    private String equipments;

    private String weapons;

    private List<MemberDto> teamsUri;

}