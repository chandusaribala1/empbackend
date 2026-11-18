package com.example.employee.auth;

import com.example.employee.dto.EmployeeResponse;

public record AuthUserResponse(String username, String role, EmployeeResponse employee) {}
