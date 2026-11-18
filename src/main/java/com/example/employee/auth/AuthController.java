package com.example.employee.auth;

import com.example.employee.dto.EmployeeResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/me")
    public AuthUserResponse currentUser(Authentication authentication) {
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));
        return authService.currentUser(authentication.getName(), isAdmin);
    }

    @PostMapping("/register")
    public ResponseEntity<EmployeeResponse> register(@Valid @RequestBody EmployeeRegistrationRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @PostMapping("/accounts/{employeeId}")
    public EmployeeResponse createEmployeeLogin(
            @PathVariable Long employeeId,
            @Valid @RequestBody EmployeeLoginRequest request) {
        return authService.createEmployeeLogin(employeeId, request);
    }
}
