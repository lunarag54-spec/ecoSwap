package com.ecoswap.backend.dto;

import com.ecoswap.backend.entity.Product.Condition;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Data;

import java.math.BigDecimal;

@Data
public class ProductRequest {
    @NotBlank
    private String title;

    private String description;

    @NotNull @Positive
    private BigDecimal price;

    @NotBlank
    private String category;

    @NotNull
    private Condition condition;

    private String imageUrl;
}