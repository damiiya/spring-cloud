package com.welab.api_gateway.security.jwt;

import com.welab.api_gateway.security.jwt.authentification.JwtAuthentication;
import com.welab.api_gateway.security.jwt.authentification.UserPrincipal;
import com.welab.api_gateway.security.jwt.props.JwtConfigProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtTokenValidator {

    private final JwtConfigProperties configProperties;
    private volatile SecretKey secretKey;

    /*
    * <JWT 검증 시크릿 키 초기화 & 반환>
    * config에 등록된 base64 문자열을 SecretKey로 변환
    * 최초 한 번만 생성되도록 지연 초기화(lazy initialization) + 동기화 처리
    *  */
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
    * <JWT 유효성 검증 & 사용자 인증 정보 생성>
    * 토큰이 유효하지 않으면 null 반환
    * 유저 ID 및 토큰 타입(claims)을 확인
    * 유저 정보를 담은 UserPrincipal, 권한 리스트와 함께 JwtAuthentication 객체 생성
    * */
    public JwtAuthentication validateToken(String token) {
        String userId = null;
        final Claims claims = this.verifyAndGetClaims(token);

        if (claims == null) {
            return null;
        }

        Date expirationDate = claims.getExpiration();

        if (expirationDate == null || expirationDate.before(new Date())) {
            return null;
        }

        userId = claims.get("userId", String.class);
        String tokenType = claims.get("tokenType", String.class);

        if (!"access".equals(tokenType)) {
            return null;
        }

        UserPrincipal principal = new UserPrincipal(userId);

        return new JwtAuthentication(principal, token, getGrantedAuthorities("user"));
    }

    /*
    * <JWT 서명 검증 & claim 정보 추출>
    * 내부적으로 서명 키로 JWT를 파싱
    * 성공 시 claims 객체 반환, 실패 시 null
    * validateToken()에서 호출되어 실제 검증 수행
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
    * <주어진 역할(role) - Spring Security의 GrantedAuthority로 변환>
    * 권한을 가진 인증 객체를 만들기 위해 사용
    * 기본적으로 “user” 권한을 가정
    * */
    private List<GrantedAuthority> getGrantedAuthorities(String role) {
        ArrayList<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        if (role != null) {
            grantedAuthorities.add(new SimpleGrantedAuthority(role));
        }

        return grantedAuthorities;
    }

    /*
    * <HTTP 요청 헤더에서 JWT(Access Token) 추출>
    * "Authorization" 헤더에서 "Bearer "로 시작하는 토큰을 추출
    * 프론트엔드가 보낸 요청에서 토큰을 꺼내는 역할
    * */
    public String getToken(HttpServletRequest request) {
        String authHeader = getAuthHeaderFromHeader(request);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    /*
    * <JWT 토큰이 들어있는 HTTP 헤더 값 가져오기>
    * 실제 헤더 이름은 configProperties.getHeader()로 설정값을 따름
    * "Authorization" 또는 설정된 다른 이름일 수 있음
    * */
    private String getAuthHeaderFromHeader(HttpServletRequest request) {
        return request.getHeader(configProperties.getHeader());
    }

}