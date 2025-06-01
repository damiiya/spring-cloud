package com.welab.backend_user.secret.jwt;

import com.welab.backend_user.secret.jwt.dto.TokenDto;
import com.welab.backend_user.secret.jwt.props.JwtConfigProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
@RequiredArgsConstructor
public class TokenGenerator {
    private final JwtConfigProperties configProperties;
    private volatile SecretKey secretKey;

    /*
    * <SecretKey 초기화>
    * 지연 초기화(Lazy Initialization) + Double-Checked Locking 패턴을 통해 secretKey를 단 한 번만 생성
    * Base64로 인코딩된 secret key 문자열을 디코딩해 HMAC-SHA 서명 키로 변환
    * */
    private SecretKey getSecretKey() {
        if (secretKey == null) {
            synchronized (this) {
                if (secretKey == null) {
                    secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(configProperties.getSecretKey()));
                }
            }
        }
        return secretKey;
    }

    /*
    * <액세스 토큰 생성>
    * 단일 Access Token을 발급
    * 내부적으로 generateJwtToken() 호출
    * */
    public TokenDto.AccessToken generateAccessToken(String userId, String deviceType) {
        TokenDto.JwtToken jwtToken = this.generateJwtToken(userId, deviceType, false);
        return new TokenDto.AccessToken(jwtToken);
    }

    /*
    * <액세스+리프레시 토큰 생성>
    * Access Token과 Refresh Token을 동시에 발급
    * Refresh 토큰: 일반적으로 더 긴 만료시간
    * */
    public TokenDto.AccessRefreshToken generateAccessRefreshToken(String userId, String deviceType) {
        TokenDto.JwtToken accessJwtToken = this.generateJwtToken(userId, deviceType, false);
        TokenDto.JwtToken refreshJwtToken = this.generateJwtToken(userId, deviceType, true);
        return new TokenDto.AccessRefreshToken(accessJwtToken, refreshJwtToken);
    }

    /*
    * <JWT 생성 핵심 로직>
    * tokenExpiresIn()을 통해 만료 시간을 계산하고,
    * JWT의 issuer, subject, 커스텀 claim (userId, deviceType, tokenType) 등을 설정
    * JWT는 secretKey로 서명되고 compact 문자열로 반환
    * TokenDto.JwtToken 객체로 만료 시간과 함께 래핑되어 반환
    * */
    public TokenDto.JwtToken generateJwtToken(String userId,
                                              String deviceType,
                                              boolean refreshToken
    ) {
        int tokenExpiresIn = tokenExpiresIn(refreshToken, deviceType);
        String tokenType = refreshToken ? "refresh" : "access";
        String token = Jwts.builder()
                .issuer("welab")
                .subject(userId)
                .claim("userId", userId)
                .claim("deviceType", deviceType)
                .claim("tokenType", tokenType)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + tokenExpiresIn * 1000L))
                .signWith(getSecretKey())
                .header().add("typ", "JWT")
                .and()
                .compact();
        return new TokenDto.JwtToken(token, tokenExpiresIn);
    }

    /*
    * <토큰 유효성 검증>
    * verifyAndGetClaims()로 파싱 → 클레임 추출
    * 만료 여부 확인: claims.getExpiration()이 현재 시각 이후
    * 토큰 타입이 "refresh"인지 확인
    * 위 조건을 모두 통과하면 userId 반환, 실패 시 null
    * */
    public String validateJwtToken(String refreshToken) {
        String userId = null;
        final Claims claims = this.verifyAndGetClaims(refreshToken);

        if (claims == null) {
            return null;
        }

        Date expirationDate = claims.getExpiration();
        if (expirationDate == null || expirationDate.before(new Date())) {
            return null;
        }

        userId = claims.get("userId", String.class);
        String tokenType = claims.get("tokenType", String.class);

        if (!"refresh".equals(tokenType)) {
            return null;
        }

        return userId;
    }

    /*
    * <클레임 검증>
    * 서명 검증 및 파싱
    * 예외 발생 시 null 반환
    * */
    private Claims verifyAndGetClaims(String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }

    /*
    * <만료 시간 계산>
    * Access Token은 기본적으로 15분(60×15초)
    * Refresh Token일 경우, deviceType에 따라 각각 다르게 설정
    *   - WEB -> expiresIn
    *   - MOBILE -> mobileExpiresIn
    *   - TABLET -> tabletExpiresIn
    *   - null 또는 기본값 -> expiresIn
    * */
    private int tokenExpiresIn(boolean refreshToken, String deviceType) {
        int expiresIn = 60 * 15;

        if (refreshToken) {
            if (deviceType != null) {
                if (deviceType.equals("WEB")) {
                    expiresIn = configProperties.getExpiresIn();
                } else if (deviceType.equals("MOBILE")) {
                    expiresIn = configProperties.getMobileExpiresIn();
                } else if (deviceType.equals("TABLET")) {
                    expiresIn = configProperties.getTabletExpiresIn();
                } else {
                    expiresIn = configProperties.getExpiresIn();
                }
            } else {
                expiresIn = configProperties.getExpiresIn();
            }
        }

        return expiresIn;
    }
}