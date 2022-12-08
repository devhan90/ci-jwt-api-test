package com.codeidea.jwtapi.dto;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenDto {

    private String grantType;
    private String token;
    private String refreshToken;
    private Long refreshTokenExpirationTime;
}
