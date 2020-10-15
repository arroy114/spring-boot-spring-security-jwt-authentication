package com.bezkoder.springjwt.security.services;

import com.bezkoder.springjwt.models.Employee;
import com.bezkoder.springjwt.repository.EmployeeRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	private final EmployeeRepository employeeRepository;

	public UserDetailsServiceImpl(EmployeeRepository employeeRepository) {
		this.employeeRepository = employeeRepository;
	}


	//load User by username and
	// returns a UserDetails object that Spring Security can use for authentication and validation
	@Override
	@Transactional
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		Employee employee = employeeRepository.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException("Email Not Found with email: " + email));

		return UserDetailsImpl.build(employee);
	}

}
