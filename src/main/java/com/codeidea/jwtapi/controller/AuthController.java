package com.codeidea.jwtapi.controller;

import com.codeidea.jwtapi.dto.LoginDto;
import com.codeidea.jwtapi.dto.Response;
import com.codeidea.jwtapi.dto.TokenDto;
import com.codeidea.jwtapi.dto.UserDto;
import com.codeidea.jwtapi.jwt.JwtFilter;
import com.codeidea.jwtapi.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api")
public class AuthController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RedisTemplate redisTemplate;
    private final Response response;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder, RedisTemplate redisTemplate, Response response) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.redisTemplate = redisTemplate;
        this.response = response;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        TokenDto tokenDto = tokenProvider.createToken(authentication);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + tokenDto.getToken());

        UserDetails userDetail = (UserDetails) authentication.getPrincipal();
        String username = userDetail.getUsername();

        // RefreshToken Redis ?????? (expirateTime ????????? ?????? ?????? ?????? ??????)
        redisTemplate.opsForValue()
                .set("RT:" + username, tokenDto.getRefreshToken(), tokenDto.getRefreshTokenExpirationTime(), TimeUnit.MILLISECONDS);

        return new ResponseEntity<>(tokenDto, httpHeaders, HttpStatus.OK);
    }

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(@Valid @RequestBody UserDto userDto) {
        // 1. Refresh Token ??????
        if (!tokenProvider.validateToken(userDto.getRefreshToken())) {
            return response.fail("Refresh Token ????????? ???????????? ????????????.", HttpStatus.BAD_REQUEST);
        }

        // 2. Access Token ?????? User email ??? ???????????????.
        Authentication authentication = tokenProvider.getAuthentication(userDto.getAccessToken());

        // 3. Redis ?????? User email ??? ???????????? ????????? Refresh Token ?????? ???????????????.
        String refreshToken = (String)redisTemplate.opsForValue().get("RT:" + authentication.getName());
        // (??????) ?????????????????? Redis ??? RefreshToken ??? ???????????? ?????? ?????? ??????
        if(ObjectUtils.isEmpty(refreshToken)) {
            return response.fail("????????? ???????????????.", HttpStatus.BAD_REQUEST);
        }
        if(!refreshToken.equals(userDto.getRefreshToken())) {
            return response.fail("Refresh Token ????????? ???????????? ????????????.", HttpStatus.BAD_REQUEST);
        }

        // 4. ????????? ?????? ??????
        TokenDto tokenDto = tokenProvider.createToken(authentication);

        // 5. RefreshToken Redis ????????????
        redisTemplate.opsForValue()
                .set("RT:" + authentication.getName(), tokenDto.getRefreshToken(), tokenDto.getRefreshTokenExpirationTime(), TimeUnit.MILLISECONDS);

        return response.success(tokenDto, "Token ????????? ?????????????????????.", HttpStatus.OK);
    }
}
