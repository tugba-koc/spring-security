package devtugba.security.config.concretes;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtManager {

    private static final String SECRET_KEY = "+VWFF3SI1dG3ejmx4f/jRWVF1fvFfcUqiV7xFxHZqLULhC+PA4DrRBHYpSrsuHyq1+21AYsclRbSJuHzSjCYooUKf5iK7BlLIHZ5AJ64N3OjWVVjj8qfs5VTdx0oV1Z/hvIcsWbu911TD7TMQsBN1cgLWaDrC0kekqVsPJK7XCOyuX8NZGzyRL1fXpF+gZqQGtfy0HhN8CVNt74mjITADIG1cVBsL6l4CkCTa6PSuSVyd/bxVB+neTiqGQBPfg14fsSRyfJEq2E0KT3Ka0rOw779xRVQ72qmkuNyRpESGnTqYfg1HZyQYq84leSm6wL3yi71uUiodHTbnI3WI0kyTp02vO7QQS5lxekxMGl8zOU=";

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts
        .builder()
        .setClaims(extraClaims)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)
        .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver ){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){
        return Jwts
        .parserBuilder()
        .setSigningKey(getSignInKey())
        .build()
        .parseClaimsJws(token)
        .getBody();
    }

    private Key getSignInKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isTokenValid(String token,  UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token, userDetails));
    }

    private boolean isTokenExpired(String token, UserDetails userDetails){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    
}
