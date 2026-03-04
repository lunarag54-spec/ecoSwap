package com.ecoswap.backend.repository;

import com.ecoswap.backend.entity.Product;
import com.ecoswap.backend.entity.Product.Condition;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.math.BigDecimal;
import java.util.List;

public interface ProductRepository extends JpaRepository<Product, Long> {

    List<Product> findByUserId(Long userId);

    List<Product> findByCategoryAndIsActiveTrue(String category);

    List<Product> findByConditionAndIsActiveTrue(Condition condition);

    @Query("SELECT p FROM Product p WHERE p.isActive = true " +
            "AND (:category IS NULL OR p.category = :category) " +
            "AND (:condition IS NULL OR p.condition = :condition) " +
            "AND (:minPrice IS NULL OR p.price >= :minPrice) " +
            "AND (:maxPrice IS NULL OR p.price <= :maxPrice)")
    List<Product> search(
            @Param("category") String category,
            @Param("condition") Condition condition,
            @Param("minPrice") BigDecimal minPrice,
            @Param("maxPrice") BigDecimal maxPrice
    );
}