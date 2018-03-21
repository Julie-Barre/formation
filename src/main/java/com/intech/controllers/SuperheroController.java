package com.intech.controllers;

import com.intech.dto.SuperheroDto;
import io.swagger.annotations.ApiOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import com.intech.services.SuperheroService;

import javax.validation.Valid;

@Controller
@CrossOrigin
@RequestMapping("/superheroes")
public class SuperheroController {

	private static Logger logger = LoggerFactory.getLogger(SuperheroController.class);

	@Autowired
	private SuperheroService superheroService;

	@ApiOperation(
			value = "Retrieve the full heroes list"
	)
	@GetMapping
	public @ResponseBody Iterable<SuperheroDto> getAllSuperHeroes() {
		logger.info("GET /superheroes");
		return superheroService.findAllSuperHeroes();
	}

	@ApiOperation(
			value = "Retrieve information about a specific superhero"
	)
	@GetMapping(value = "/{id}")
	public @ResponseBody
	SuperheroDto getASuperHero(@PathVariable Long id) {
		logger.info("GET /superheroes/" + id);
		return superheroService.findSuperHeroById(id);
		// TODO : Java formation => handle no such element Exception
	}

	@ApiOperation(
			value = "Uptade information of a specific superhero"
	)
	@PutMapping(value = "/{id}")
	public void updateASuperHero(@PathVariable Long id, @RequestBody @Valid SuperheroDto superHero) {
		logger.info("PUT /superheroes/" + id);
		superheroService.updateSuperHero(id, superHero);
	}

}