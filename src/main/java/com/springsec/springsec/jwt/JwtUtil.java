package com.springsec.springsec.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;


@Service
public class JwtUtil {

    // hash işlemi yaparken kullanılacak key
    private String SECRET_KEY = "cozef";

    // verilen token a ait kullanıcı adını döndürür.
    public String extractUsername(String token) {
        DecodedJWT jwt = JWT.decode(token);
        return jwt.getSubject();
    }

    // verilen token a ait token bitiş süresini verir.
    public Date extractExpiration(String token) {
        DecodedJWT jwt = JWT.decode(token);
        return jwt.getExpiresAt();
    }

    // token ın geçerlilik süre doldu mu?
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // userDetails objesini alır. createToken metoduna gönderir.
    public String generateToken(UserDetails userDetails) {
        return createToken(userDetails.getUsername());
    }

    private String createToken(String subject){
        Algorithm alg = Algorithm.HMAC256(SECRET_KEY);
        return JWT.create()
                .withSubject(subject) // ilgili kullanıcı
                .withIssuedAt(new Date(System.currentTimeMillis())) // başlangıç
                .withExpiresAt(new Date(System.currentTimeMillis() + 5 * 60 * 60 * 1000)) // bitiş
                .sign(alg); // kullanılan algoritma ve bu algoritma çalışırken kullanılacak hash key değeri

    }

    // token hala geçerli mi? kullanıcı adı doğru ise ve token ın geçerlilik süresi devam ediyorsa true döner.
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
