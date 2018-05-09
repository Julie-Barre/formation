package com.intech.services;

import com.intech.api.AuthRequestDto;

import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final String mockUser = "formation";
    private final String mockPassword = "formation";

    public boolean login(AuthRequestDto authRequestDto){
        if(authRequestDto != null && mockUser.equals(authRequestDto.getUsername()) && mockPassword.equals(authRequestDto.getPassword())){
            return true;
        } else {
            return false;
        }
    }

}
