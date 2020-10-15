package com.bezkoder.springjwt.bootstrap;

import com.bezkoder.springjwt.models.Role;
import com.bezkoder.springjwt.models.RoleEnum;
import com.bezkoder.springjwt.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataLoader implements CommandLineRunner {

    private final RoleRepository roleRepository;

    public DataLoader(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public void run(String... args) throws Exception {

        loadRoles();
    }

    private void loadRoles() {
        Role role1 = new Role();
        role1.setName(RoleEnum.ROLE_USER);
        roleRepository.save(role1);

        Role role2 = new Role();
        role2.setName(RoleEnum.ROLE_MODERATOR);
        roleRepository.save(role2);

        Role role3 = new Role();
        role3.setName(RoleEnum.ROLE_ADMIN);
        roleRepository.save(role3);
    }
}
