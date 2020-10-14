package com.bezkoder.springjwt.repository;

import com.bezkoder.springjwt.models.Employee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<Employee, Long> {
	Optional<Employee> findByEmail(String email);
	Boolean existsByEmail(String email);
}
