package com.intech.controllers;

import com.intech.api.AuthRequestDto;
import com.intech.api.AuthResultDto;
import com.intech.services.AuthService;
import com.intech.services.JwtService;

import io.swagger.annotations.ApiOperation;
import lombok.extern.java.Log;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Log
@RestController
@CrossOrigin
@RequestMapping("/authenticate")
public class AuthController {
    
    @Autowired
    private AuthService authService;
    
    @Autowired
    private JwtService jwtService;

	public AuthController(AuthService authService){
		this.authService = authService;
	}

	@ApiOperation(value = "Login with credentials")
	@PostMapping(value = "")
	public ResponseEntity<AuthResultDto> fightSuperheroes(@RequestBody AuthRequestDto authRequestDto) {
		log.info("POST /authenticate");
        boolean authenticated =  authService.login(authRequestDto);
        if (authenticated) {
            String jwtToken = jwtService.generateJwt(authRequestDto.getUsername());
            log.info("jwtToken : " + jwtToken);
            return ResponseEntity.accepted().body(new AuthResultDto(jwtToken));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }
    }
}
