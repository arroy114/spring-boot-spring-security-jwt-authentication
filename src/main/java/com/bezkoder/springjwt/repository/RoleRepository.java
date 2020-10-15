package com.bezkoder.springjwt.repository;

import com.bezkoder.springjwt.models.Role;
import com.bezkoder.springjwt.models.RoleEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
	Optional<Role> findByName(RoleEnum name);
}
