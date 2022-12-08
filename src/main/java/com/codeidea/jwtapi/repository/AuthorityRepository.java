package com.codeidea.jwtapi.repository;

import com.codeidea.jwtapi.entity.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorityRepository extends JpaRepository<Authority, String> {
}
