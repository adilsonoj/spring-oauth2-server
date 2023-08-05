package com.oliveira.authorization.server.oauth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oliveira.authorization.server.oauth.model.Usuario;


public interface UserRepository extends JpaRepository<Usuario, Long>{
    Optional<Usuario> findByUsername(String username);
}
