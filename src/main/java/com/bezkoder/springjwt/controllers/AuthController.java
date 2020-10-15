package com.bezkoder.springjwt.controllers;

import com.bezkoder.springjwt.models.Employee;
import com.bezkoder.springjwt.models.Role;
import com.bezkoder.springjwt.models.RoleEnum;
import com.bezkoder.springjwt.payload.request.LogInDTO;
import com.bezkoder.springjwt.payload.request.SignUpDTO;
import com.bezkoder.springjwt.payload.response.JwtDTO;
import com.bezkoder.springjwt.payload.response.MessageDTO;
import com.bezkoder.springjwt.repository.EmployeeRepository;
import com.bezkoder.springjwt.repository.RoleRepository;
import com.bezkoder.springjwt.security.jwt.JwtUtils;
import com.bezkoder.springjwt.security.services.UserDetailsImpl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final AuthenticationManager authenticationManager; //authenticationManager bean is created by WebSecurityConfig, which uses WebSecurityConfigurerAdapter own authenticationManagerBean
	private final PasswordEncoder encoder; //encoder bean is created by WebSecurityConfig and method used is BCrypt
	private final JwtUtils jwtUtils;
	private final EmployeeRepository employeeRepository;
	private final RoleRepository roleRepository;

	public AuthController(AuthenticationManager authenticationManager, EmployeeRepository employeeRepository, RoleRepository roleRepository, PasswordEncoder encoder, JwtUtils jwtUtils) {
		this.authenticationManager = authenticationManager;
		this.employeeRepository = employeeRepository;
		this.roleRepository = roleRepository;
		this.encoder = encoder;
		this.jwtUtils = jwtUtils;
	}

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LogInDTO loginDTO) {

		//Authenticate and return an Authentication object that can be used to find user information
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword()));

		//Update SecurityContext using Authentication object
		SecurityContextHolder.getContext().setAuthentication(authentication);

		//Generate JWT
		String jwt = jwtUtils.generateJwtToken(authentication);

		//Get UserDetails from Authentication object
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal(); //authentication.getPrincipal() return object of org.springframework.security.core.userdetails.User

		//Get roles from UserDetails
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());

		//Response that contains JWT, id, email and roles
		return ResponseEntity.ok(new JwtDTO(jwt,
												 userDetails.getId(),
												 userDetails.getEmail(),
												 roles));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpDTO signUpDTO) {

		//Check if email exist by userRepository
		if (employeeRepository.existsByEmail(signUpDTO.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageDTO("Error: Email is already in use!"));
		}

		// Create new user's account
		Employee employee = new Employee(signUpDTO.getEmail(),
							 encoder.encode(signUpDTO.getPassword())); //encoder bean is created in WebSecurityConfig and method used is BCrypt

		//Adding role to the created employee
		Set<String> strRoles = signUpDTO.getRoles();
		Set<Role> roles = new HashSet<>();
		if (strRoles == null) {
			Role userRole = roleRepository.findByName(RoleEnum.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName(RoleEnum.ROLE_ADMIN)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(adminRole);

					break;
				case "mod":
					Role modRole = roleRepository.findByName(RoleEnum.ROLE_MODERATOR)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(modRole);

					break;
				default:
					Role userRole = roleRepository.findByName(RoleEnum.ROLE_USER)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}
		employee.setRoles(roles);
		employeeRepository.save(employee);

		return ResponseEntity.ok(new MessageDTO("User registered successfully!"));
	}
}
