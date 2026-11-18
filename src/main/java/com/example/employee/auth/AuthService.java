package com.example.employee.auth;

import com.example.employee.dto.EmployeeResponse;
import com.example.employee.entity.Employee;
import com.example.employee.exception.DuplicateResourceException;
import com.example.employee.exception.EmployeeNotFoundException;
import com.example.employee.repository.EmployeeRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import org.springframework.jdbc.core.JdbcTemplate;

@Service
public class AuthService {
    private final EmployeeRepository employees;
    private final PasswordEncoder passwordEncoder;
    private final JdbcTemplate jdbcTemplate;

    public AuthService(
            EmployeeRepository employees,
            PasswordEncoder passwordEncoder, JdbcTemplate jdbcTemplate) {
        this.employees = employees;
        this.passwordEncoder = passwordEncoder;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional
    public EmployeeResponse register(EmployeeRegistrationRequest request) {
        String username = request.username().trim().toLowerCase(Locale.ROOT);
        String email = request.email().trim();

        if (isAdminUsername(username)) {
            throw new DuplicateResourceException("That username is reserved");
        }
        if (employees.existsByUsernameIgnoreCase(username)) {
            throw new DuplicateResourceException("That username is already registered");
        }
        if (employees.existsByEmailIgnoreCase(email)) {
            throw new DuplicateResourceException("That email already has an employee profile");
        }

        Employee employee = new Employee(request.name().trim(), email, null, null);
        employee.setUsername(username);
        employee.setPasswordHash(passwordEncoder.encode(request.password()));
        return toResponse(employees.save(employee));
    }

    @Transactional
    public EmployeeResponse createEmployeeLogin(Long employeeId, EmployeeLoginRequest request) {
        String username = request.username().trim().toLowerCase(Locale.ROOT);
        if (isAdminUsername(username)) {
            throw new DuplicateResourceException("That username is reserved");
        }

        Employee employee = employees.findById(employeeId)
                .orElseThrow(() -> new EmployeeNotFoundException(employeeId));
        Employee otherAccount = employees.findByUsernameIgnoreCase(username).orElse(null);
        if (otherAccount != null && !otherAccount.getId().equals(employeeId)) {
            throw new DuplicateResourceException("That username is already registered");
        }

        employee.setUsername(username);
        employee.setPasswordHash(passwordEncoder.encode(request.password()));
        return toResponse(employees.save(employee));
    }

    @Transactional(readOnly = true)
    public AuthUserResponse currentUser(String username, boolean isAdmin) {
        if (isAdmin) {
            return new AuthUserResponse(username, "ADMIN", null);
        }

        Employee employee = employees.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new IllegalArgumentException("Employee account was not found"));
        return new AuthUserResponse(employee.getUsername(), "EMPLOYEE", toResponse(employee));
    }

    private boolean isAdminUsername(String username) {
        Integer count = jdbcTemplate.queryForObject(
                "select count(*) from employee.admin_users where lower(username) = lower(?)",
                Integer.class, username);
        return count != null && count > 0;
    }

    private EmployeeResponse toResponse(Employee employee) {
        return new EmployeeResponse(
                employee.getId(), employee.getName(), employee.getEmail(), employee.getSalary(),
                employee.getDepartment() == null ? null : employee.getDepartment().getId(),
                employee.getDepartment() == null ? null : employee.getDepartment().getName());
    }
}
