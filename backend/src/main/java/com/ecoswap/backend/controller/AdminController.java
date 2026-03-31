package com.ecoswap.backend.controller;

import com.ecoswap.backend.dto.ProductResponse;
import com.ecoswap.backend.entity.User;
import com.ecoswap.backend.repository.ProductRepository;
import com.ecoswap.backend.repository.UserRepository;
import com.ecoswap.backend.service.ProductService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")   // Todos los endpoints de esta clase requieren rol ADMIN
public class AdminController {

    private final UserRepository userRepository;
    private final ProductRepository productRepository;
    private final ProductService productService;

    public AdminController(UserRepository userRepository,
            ProductRepository productRepository,
            ProductService productService) {
        this.userRepository = userRepository;
        this.productRepository = productRepository;
        this.productService = productService;
    }

    // Listar todos los usuarios
    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }

    // Eliminar un usuario (y sus productos por cascade)
    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    // Listar todos los productos (de todos los usuarios)
    @GetMapping("/products")
    public ResponseEntity<List<ProductResponse>> getAllProducts() {
        List<ProductResponse> products = productRepository.findAll()
                .stream()
                .map(productService::mapToResponse)   // reutilizamos el mapper
                .toList();
        return ResponseEntity.ok(products);
    }

    // Eliminar cualquier producto
    @DeleteMapping("/products/{id}")
    public ResponseEntity<Void> deleteProduct(@PathVariable Long id) {
        productRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }
}