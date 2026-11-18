package com.example.employee.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record EmployeeRegistrationRequest(
        @NotBlank @Size(min = 3, max = 50)
        @Pattern(regexp = "^[A-Za-z0-9._-]+$", message = "Username may contain letters, numbers, dot, underscore, and dash")
        String username,
        @NotBlank @Size(min = 8, max = 100) String password,
        @NotBlank @Size(max = 120) String name,
        @NotBlank @Email
        @Pattern(regexp = "(?i)^[A-Za-z0-9._%+-]+@gmail\\.com$", message = "Email must use the format example@gmail.com")
        @Size(max = 254) String email) {}
