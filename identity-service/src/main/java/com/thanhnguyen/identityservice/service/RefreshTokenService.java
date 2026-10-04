package com.thanhnguyen.identityservice.service;

import com.thanhnguyen.identityservice.entity.RefreshToken;
import com.thanhnguyen.identityservice.entity.User;
import com.thanhnguyen.identityservice.exception.TokenRefreshException;
import com.thanhnguyen.identityservice.exception.UserNotFoundException;
import com.thanhnguyen.identityservice.repository.RefreshTokenRepository;
import com.thanhnguyen.identityservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    @Value("${app.jwt.refresh-token-expiration}") private long refreshTokenExpiration;

    public RefreshToken createRefreshToken(String userId)
    {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpiration));
        refreshToken.setUser(user);
        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token)
    {
        if(token.getExpiryDate().isBefore(Instant.now()))
        {
            refreshTokenRepository.deleteById(token.getId());
            throw new TokenRefreshException("Refresh token expired, please login again");
        }
        return token;
    }
}
