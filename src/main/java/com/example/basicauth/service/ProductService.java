package com.example.basicauth.service;

import com.example.basicauth.model.Product;
import com.example.basicauth.model.UserInfo;

import java.util.List;

public interface ProductService {

    List<Product> getAllPost();

    Product createProduct(Product product);

    UserInfo createUserInfo(UserInfo userInfo);
}
