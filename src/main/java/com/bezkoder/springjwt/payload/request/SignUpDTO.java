package com.bezkoder.springjwt.payload.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.Set;

@Data @NoArgsConstructor @AllArgsConstructor
public class SignUpDTO {

    @NotBlank @Size(max = 50) @Email
    private String email;

    @NotBlank @Size(min = 6, max = 40)
    private String password;

    private Set<String> roles;
}
