package com.bezkoder.springjwt.security.services;

import com.bezkoder.springjwt.models.Employee;
import com.bezkoder.springjwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	private final UserRepository userRepository;

	public UserDetailsServiceImpl(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	@Transactional
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		Employee employee = userRepository.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException("Email Not Found with email: " + email));

		return UserDetailsImpl.build(employee);
	}

}
