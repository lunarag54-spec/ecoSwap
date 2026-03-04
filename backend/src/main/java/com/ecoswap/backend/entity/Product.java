package com.ecoswap.backend.entity;

import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "products")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 150)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(nullable = false, precision = 10, scale = 2)
    private BigDecimal price;

    @Column(nullable = false)
    private String category; // videogames, music, collectibles, clothing, other

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Condition condition;

    private String imageUrl;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    private boolean isActive = true;

    private LocalDateTime createdAt = LocalDateTime.now();

    public enum Condition {
        NEW, LIKE_NEW, GOOD, FAIR, POOR
    }
}