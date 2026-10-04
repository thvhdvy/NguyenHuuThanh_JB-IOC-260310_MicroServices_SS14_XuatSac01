package com.thanhnguyen.identityservice.service;

import com.thanhnguyen.identityservice.dto.*;
import com.thanhnguyen.identityservice.entity.RefreshToken;
import com.thanhnguyen.identityservice.entity.User;
import com.thanhnguyen.identityservice.exception.DuplicateUsernameException;
import com.thanhnguyen.identityservice.exception.InvalidCredentialsException;
import com.thanhnguyen.identityservice.exception.TokenRefreshException;
import com.thanhnguyen.identityservice.exception.UserNotFoundException;
import com.thanhnguyen.identityservice.repository.RefreshTokenRepository;
import com.thanhnguyen.identityservice.repository.UserRepository;
import com.thanhnguyen.identityservice.security.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class    AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final StringRedisTemplate redisTemplate;
    private final JwtUtil jwtUtil;
    public UserResponse register(RegisterRequest request)
    {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateUsernameException(request.getUsername());
        }

        User user = new User(
                UUID.randomUUID().toString(),
                request.getUsername(),
                passwordEncoder.encode(request.getPassword()),
                request.getRole()
        );

        User savedUser = userRepository.save(user);
        return new UserResponse(savedUser.getId(), savedUser.getUsername(), savedUser.getRole());
    }

    public String generateTestToken(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UserNotFoundException(username));
        return jwtUtil.generateAccessToken(user);
    }

    public LoginResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername()).orElseThrow(InvalidCredentialsException::new);
        if(passwordEncoder.matches(request.getPassword(), user.getPassword()))
        {
            String accessToken = jwtUtil.generateAccessToken(user);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());
            return new LoginResponse(accessToken, refreshToken.getToken());
        }
        throw new InvalidCredentialsException();
    }

    @Transactional
    public LoginResponse refreshToken(String refreshToken) {
        RefreshToken old = refreshTokenRepository.findByToken(refreshToken).orElseThrow(() -> new TokenRefreshException("Token not found"));
        refreshTokenService.verifyExpiration(old);
        User user = old.getUser();
        refreshTokenRepository.delete(old);
        String newAccessToken = jwtUtil.generateAccessToken(user);
        RefreshToken newRt = refreshTokenService.createRefreshToken(user.getId());
        return new LoginResponse(newAccessToken, newRt.getToken());
    }

    public void logout(String token) {

        Claims claims;

        try
        {
            claims = jwtUtil.parseClaims(token);
            if(claims.getId() == null)
            {
                throw new InvalidCredentialsException();
            }
        }
        catch (JwtException | IllegalArgumentException e)
        {
            throw new InvalidCredentialsException();
        }
        long ttlMs = claims.getExpiration().getTime() - System.currentTimeMillis();
        if (ttlMs > 0)
        {
            redisTemplate.opsForValue().set("blacklist:" + claims.getId(), "revoked", Duration.ofMillis(ttlMs));
        }
    }
}
