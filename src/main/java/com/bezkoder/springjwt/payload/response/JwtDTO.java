package com.bezkoder.springjwt.payload.response;

import lombok.Data;

import java.util.List;

@Data
public class JwtDTO {
	private String token;
	private String type = "Bearer";
	private Long id;
	private String email;
	private List<String> roles;

	public JwtDTO(String accessToken, Long id, String email, List<String> roles) {
		this.token = accessToken;
		this.id = id;
		this.email = email;
		this.roles = roles;
	}
}
