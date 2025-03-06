package com.irojas.demojwt.Auth;

import com.irojas.demojwt.User.UserDTO;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.irojas.demojwt.Jwt.JwtService;
import com.irojas.demojwt.User.Role;
import com.irojas.demojwt.User.User;
import com.irojas.demojwt.User.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // Autenticamos las credenciales
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        // Generamos el token
        String token = jwtService.getToken(user);

        UserDTO userDTO = new UserDTO(
                user.getUsername(),
                user.getEmail(),
                user.getFirstname(),
                user.getLastname(),
                user.getCountry()
        );

        // Retornamos la información del usuario + token
        return AuthResponse.builder()
                .token(token)
                .user(userDTO)
                .build();
    }

    public AuthResponse register(RegisterRequest request) {
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .country(request.getCountry())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER) // Asignando el rol USER por defecto
                .build();

        userRepository.save(user);
        String token = jwtService.getToken(user);

        UserDTO userDTO = new UserDTO(
                user.getUsername(),
                user.getEmail(),
                user.getFirstname(),
                user.getLastname(),
                user.getCountry()
        );

        return AuthResponse.builder()
                .token(token)
                .user(userDTO)
                .build();
    }
}

