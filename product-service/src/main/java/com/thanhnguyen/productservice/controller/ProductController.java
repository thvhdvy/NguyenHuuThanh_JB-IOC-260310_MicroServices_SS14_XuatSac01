package com.thanhnguyen.productservice.controller;

import com.thanhnguyen.productservice.model.Product;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final List<Product> productList = new CopyOnWriteArrayList<>(List.of(
            new Product(1L, "Apple", 4040),
            new Product(2L, "Samsung", 5050),
            new Product(3L, "Huanwei", 6060),
            new Product(4L, "Oppo", 7070)
            ));

    @GetMapping
    public ResponseEntity<List<Product>> findAll()
    {
        return new ResponseEntity<>(this.productList, HttpStatus.OK);
    }


    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteProductById(@PathVariable Long id)
    {
        if(!this.productList.removeIf(p -> Objects.equals(p.getId(), id)))
        {
            return new ResponseEntity<>("Khong tim thay san pham", HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>("Da xoa san pham", HttpStatus.OK);
    }
}
