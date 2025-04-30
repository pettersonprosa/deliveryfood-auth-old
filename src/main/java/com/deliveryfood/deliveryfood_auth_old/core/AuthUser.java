package com.deliveryfood.deliveryfood_auth_old.core;

import java.util.Collections;

import org.springframework.security.core.userdetails.User;

import com.deliveryfood.deliveryfood_auth_old.domain.Usuario;

import lombok.Getter;

@Getter
public class AuthUser extends User {

	private static final long serialVersionUID = 1L;
	
	private String fullName;
	
	public AuthUser(Usuario usuario) {
		super(usuario.getEmail(), usuario.getSenha(), Collections.emptyList());
		
		this.fullName = usuario.getNome();
	}
	
}
