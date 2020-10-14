package com.bezkoder.springjwt.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.HashSet;
import java.util.Set;

@Data @NoArgsConstructor @AllArgsConstructor @Entity
public class Employee {
	@Id @GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@NotBlank @Size(max = 50) @Email
	private String email;

	@NotBlank @Size(max = 120)
	private String password;

	@ManyToMany(fetch = FetchType.LAZY)
	@JoinTable
	private Set<Role> roles = new HashSet<>();

	public Employee(String email, String password) {
		this.email = email;
		this.password = password;
	}

}
