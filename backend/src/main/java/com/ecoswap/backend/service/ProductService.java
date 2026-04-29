package com.ecoswap.backend.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import com.ecoswap.backend.dto.ProductRequest;
import com.ecoswap.backend.dto.ProductResponse;
import com.ecoswap.backend.entity.Product;
import com.ecoswap.backend.entity.User;
import com.ecoswap.backend.exception.ResourceNotFoundException;
import com.ecoswap.backend.repository.ProductRepository;
import com.ecoswap.backend.repository.UserRepository;
import org.springframework.data.domain.Page;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class ProductService {

    private final ProductRepository productRepository;
    private final UserRepository userRepository;

    public ProductService(ProductRepository productRepository, UserRepository userRepository) {
        this.productRepository = productRepository;
        this.userRepository = userRepository;
    }

    public ProductResponse createProduct(ProductRequest request) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        Product product = Product.builder()
                .title(request.getTitle())
                .description(request.getDescription())
                .price(request.getPrice())
                .category(request.getCategory())
                .condition(request.getCondition())
                .imageUrl(request.getImageUrl())
                .user(user)
                .build();

        product = productRepository.save(product);

        return mapToResponse(product);
    }

    public List<ProductResponse> getMyProducts() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        return productRepository.findByUserId(user.getId())
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public Page<ProductResponse> searchProducts(
            String category,
            Product.Condition condition,
            BigDecimal minPrice,
            BigDecimal maxPrice,
            Pageable pageable) {

        // Fix: devolver todos los productos (el catálogo no usa filtros todavía)
        Page<Product> products = productRepository.findAll(pageable);

        return products.map(this::mapToResponse);
    }

    public ProductResponse mapToResponse(Product product) {
        ProductResponse response = new ProductResponse();
        response.setId(product.getId());
        response.setTitle(product.getTitle());
        response.setDescription(product.getDescription());
        response.setPrice(product.getPrice());
        response.setCategory(product.getCategory());
        response.setCondition(product.getCondition());
        response.setImageUrl(product.getImageUrl());
        response.setUsername(product.getUser().getUsername());
        response.setCreatedAt(product.getCreatedAt());
        return response;
    }

    public ProductResponse updateProduct(Long productId, ProductRequest request) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("Usuario no encontrado"));

        Product product = productRepository.findById(productId)
                .orElseThrow(() -> new ResourceNotFoundException("Producto no encontrado"));

        // Solo el propietario puede editar
        if (!product.getUser().getId().equals(user.getId())) {
            throw new RuntimeException("No tienes permiso para editar este producto");
        }

        product.setTitle(request.getTitle());
        product.setDescription(request.getDescription());
        product.setPrice(request.getPrice());
        product.setCategory(request.getCategory());
        product.setCondition(request.getCondition());
        if (request.getImageUrl() != null && !request.getImageUrl().isEmpty()) {
            product.setImageUrl(request.getImageUrl());
        }

        product = productRepository.save(product);
        return mapToResponse(product);
    }

    public void deleteProduct(Long productId) {
        // Para el flujo de compra, eliminamos sin comprobar propietario
        Product product = productRepository.findById(productId)
                .orElseThrow(() -> new ResourceNotFoundException("Producto no encontrado"));

        productRepository.delete(product);
    }
}