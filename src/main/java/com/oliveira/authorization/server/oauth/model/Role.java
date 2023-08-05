package com.oliveira.authorization.server.oauth.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;

@Entity
@Data
public class Role {
  @GeneratedValue(strategy=GenerationType.IDENTITY)
  @Id
  private Long id;
  private String nome;
}
