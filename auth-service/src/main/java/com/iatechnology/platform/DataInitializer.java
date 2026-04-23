package com.iatechnology.platform;

import com.iatechnology.platform.entity.*;
import com.iatechnology.platform.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {

        if (roleRepository.count() == 0) {
            roleRepository.save(new Role(null, ERole.ROLE_USER));
            roleRepository.save(new Role(null, ERole.ROLE_MODERATEUR));
            roleRepository.save(new Role(null, ERole.ROLE_ADMIN));
        }

        if (userRepository.count() == 0) {
            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));

            User admin = new User();
            admin.setUsername("admin");
            admin.setEmail("admin@iatech.com");
            admin.setPassword(passwordEncoder.encode("admin123"));
            admin.setNom("Super");
            admin.setPrenom("Admin");
            admin.setEnabled(true);
            Set<Role> roles = new HashSet<>();
            roles.add(adminRole);
            admin.setRoles(roles);

            userRepository.save(admin);

            Role modRole = roleRepository.findByName(ERole.ROLE_MODERATEUR)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));

            User mod = new User();
            mod.setUsername("moderateur");
            mod.setEmail("mod@iatech.com");
            mod.setPassword(passwordEncoder.encode("mod123"));
            mod.setNom("Moderateur");
            mod.setPrenom("Test");
            mod.setEnabled(true);
            Set<Role> modRoles = new HashSet<>();
            modRoles.add(modRole);
            mod.setRoles(modRoles);

            userRepository.save(mod);
        }

    }
}
