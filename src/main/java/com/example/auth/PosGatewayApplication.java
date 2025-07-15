package com.example.auth;

import com.example.auth.Auth.AuthenticationService;
import com.example.auth.Auth.RegisterRequest;
import com.example.auth.User.User;
import com.example.auth.User.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.password.PasswordEncoder;

import static com.example.auth.User.Role.*;

@SpringBootApplication
@EnableScheduling
public class PosGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(PosGatewayApplication.class, args);
    }
    
    @Bean
    public CommandLineRunner commandLineRunner(
            AuthenticationService service,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder
    ) {
        return args -> {
            // Check if admin user already exists
            if (userRepository.findByEmail("admin@gmail.com").isEmpty()) {
                var admin = RegisterRequest.builder()
                        .firstName("admin")
                        .lastName("Admin")
                        .email("admin@gmail.com")
                        .password("root")
                        .role(ADMIN)
                        .build();

                // Create admin user directly without HTTP context
                var adminUser = User.builder()
                        .firstName(admin.getFirstName())
                        .lastName(admin.getLastName())
                        .email(admin.getEmail())
                        .password(passwordEncoder.encode(admin.getPassword()))
                        .role(admin.getRole())
                        .failedLoginAttempts(0)
                        .accountLocked(false)
                        .lockTime(null)
                        .activeSessions(0)
                        .maxConcurrentSessions(3)
                        .build();

                userRepository.save(adminUser);
                System.out.println("Admin user created: admin@gmail.com / root");
            }

            // Check if regular user already exists
            if (userRepository.findByEmail("user@gmail.com").isEmpty()) {
                var user = RegisterRequest.builder()
                        .firstName("user")
                        .lastName("user")
                        .email("user@gmail.com")
                        .password("root")
                        .role(USER)
                        .build();

                // Create regular user directly without HTTP context
                var regularUser = User.builder()
                        .firstName(user.getFirstName())
                        .lastName(user.getLastName())
                        .email(user.getEmail())
                        .password(passwordEncoder.encode(user.getPassword()))
                        .role(user.getRole())
                        .failedLoginAttempts(0)
                        .accountLocked(false)
                        .lockTime(null)
                        .activeSessions(0)
                        .maxConcurrentSessions(3)
                        .build();

                userRepository.save(regularUser);
                System.out.println("Regular user created: user@gmail.com / root");
            }

            System.out.println("Default users are ready for testing:");
            System.out.println("- Admin: admin@gmail.com / root");
            System.out.println("- User: user@gmail.com / root");
            System.out.println("Use the login endpoint to get tokens for testing.");
        };
    }
}
