package com.ead.posgateway;

import com.ead.posgateway.Auth.AuthenticationService;
import com.ead.posgateway.Auth.RegisterRequest;
import com.ead.posgateway.User.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.ead.posgateway.User.Role.*;

@SpringBootApplication
public class PosGatewayApplication {

    public static void main(String[] args) {

        SpringApplication.run(PosGatewayApplication.class, args);
    }
    
    // @Bean
    // public CommandLineRunner commandLineRunner(
    //         AuthenticationService service
    // ) {
    //     return args -> {
    //         var admin = RegisterRequest.builder()
    //                 .firstName("admin")
    //                 .lastName("Admin")
    //                 .email("admin@gmail.com")
    //                 .password("root")
    //                 .role(ADMIN)
    //                 .build();

    //         var user = RegisterRequest.builder()
    //                 .firstName("user")
    //                 .lastName("user")
    //                 .email("user@gmail.com")
    //                 .password("root")
    //                 .role(USER)
    //                 .build();

    //         System.out.println("Admin token: "+ service.register(admin).getAccessToken());
    //         System.out.println("User token: "+ service.register(user).getAccessToken());

    //     };

    // }

}
