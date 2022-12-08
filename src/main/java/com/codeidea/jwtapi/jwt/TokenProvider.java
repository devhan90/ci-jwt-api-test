package com.codeidea.jwtapi.jwt;

import com.codeidea.jwtapi.dto.TokenDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.security.auth.Subject;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean {

   private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);
   private static final String AUTHORITIES_KEY = "auth";
   private static final String BEARER_TYPE = "Bearer";
   private final String secret;
   private final long tokenValidityInMilliseconds;
   private final long refreshTokenValidityInMilliseconds;
   private Key key;

   // 86400초 = 1일
   public TokenProvider(
      @Value("${jwt.secret}") String secret,
      @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
      this.secret = secret;
      this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
      this.refreshTokenValidityInMilliseconds = 7 * 24 * 60 * 60 * 1000L; // 7일
   }

   @Override
   public void afterPropertiesSet() {
      byte[] keyBytes = Decoders.BASE64.decode(secret);
      this.key = Keys.hmacShaKeyFor(keyBytes);
   }

   public TokenDto createToken(Authentication authentication) {
      String authorities = authentication.getAuthorities().stream()
         .map(GrantedAuthority::getAuthority)
         .collect(Collectors.joining(","));

      long now = (new Date()).getTime();

      // Access Token 생성
      Date validity = new Date(now + this.tokenValidityInMilliseconds);
      String accessToken = Jwts.builder()
              .setSubject(authentication.getName())
              .claim(AUTHORITIES_KEY, authorities)
              .signWith(key, SignatureAlgorithm.HS512)
              .setExpiration(validity)
              .compact();

      // Refresh Token 생성
      Date refreshValidity = new Date(now + this.refreshTokenValidityInMilliseconds);
      String refreshToken = Jwts.builder()
              .setExpiration(refreshValidity)
              .signWith(key, SignatureAlgorithm.HS512)
              .compact();

      TokenDto tokenDto = new TokenDto();
      tokenDto.setGrantType(BEARER_TYPE);
      tokenDto.setToken(accessToken);
      tokenDto.setRefreshToken(refreshToken);
      tokenDto.setRefreshTokenExpirationTime(refreshTokenValidityInMilliseconds);

      return tokenDto;

      /*return Jwts.builder()
         .setSubject(authentication.getName())
         .claim(AUTHORITIES_KEY, authorities)
         .signWith(key, SignatureAlgorithm.HS512)
         .setExpiration(validity)
         .compact();*/
   }

   public Authentication getAuthentication(String token) {
      Claims claims = Jwts
              .parserBuilder()
              .setSigningKey(key)
              .build()
              .parseClaimsJws(token)
              .getBody();

      Collection<? extends GrantedAuthority> authorities =
         Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

      User principal = new User(claims.getSubject(), "", authorities);

      return new UsernamePasswordAuthenticationToken(principal, token, authorities);
   }

   public boolean validateToken(String token) {
      try {
         Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
         return true;
      } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
         logger.info("잘못된 JWT 서명입니다.");
      } catch (ExpiredJwtException e) {
         logger.info("만료된 JWT 토큰입니다.");
         // 이자리에서 현재 유저 고유정보에 대한 redis상의 refreshToken이 있다면?
         // 자동으로 엑세스토큰을 재발급해주면 어떨까?
         // 그런데 엑세스토큰에 대한 재발급은 모든 api에서 해줄수 있는 것도 아니고, 인증과 관련된 api에서만 해줄 수 있다.
         // 그리고 그렇게 재발급해준걸 클라이언트상에서 자바스크립트로 고유 저장소에 저장을 해야한다.
         // 때문에 이곳처럼 유효성검사를 해주는곳에 재발급을 넣어버리면, 그냥 사실상 엑세스토큰 자체가 의미가 없어진다.
         // 그렇다면 재발급해주는 api로 직접 클라이언트단의 판단으로 재요청을 보내는식으로 한다고치자.
         // 이걸 클라이언트단에서 판단을 하려면, 토큰 자체는 유효했었지만 기간이 만료되었다는 정보를 클라이언트에서 알 수 있어야 한다.
         // 그러려면 이곳에서 해줘야하는 일은 단순히 스스로 서버 콘솔에 로그를 찍는게 아니라, 클라이언트단에서 만료된 토큰으로 인한 실패라는 것을 알 수 있어야 한다는 뜻이 된다.

      } catch (UnsupportedJwtException e) {
         logger.info("지원되지 않는 JWT 토큰입니다.");
      } catch (IllegalArgumentException e) {
         logger.info("JWT 토큰이 잘못되었습니다.");
      }
      return false;
   }

}
