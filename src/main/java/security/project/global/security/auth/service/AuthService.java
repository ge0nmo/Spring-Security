package security.project.global.security.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import security.project.domain.member.entity.Member;
import security.project.domain.member.repository.MemberRepository;
import security.project.global.security.auth.repository.RedisRepository;
import security.project.global.security.jwt.JwtTokenizer;

import javax.security.auth.RefreshFailedException;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
public class AuthService
{
    private final RedisRepository redisRepository;
    private final JwtTokenizer jwtTokenizer;
    private final RedisTemplate<String, String> redisTemplate;

    public void login(String email)
    {
        String refreshToken = jwtTokenizer.generateRefreshToken(email);
        redisRepository.saveRefreshToken(refreshToken, email);
    }

    public void logout(String refreshToken)
    {
        jwtTokenizer.isValidToken(refreshToken);

        if(hasKey(refreshToken))
        {
            redisRepository.deleteRefreshToken(refreshToken);
            return;
        }

        throw new RuntimeException("expired token");
    }

    public String reissue(String accessToken, String refreshToken)
    {
        if(hasKey(refreshToken))
        {
            Claims claims = jwtTokenizer.getClaims(accessToken);
            String email = claims.getSubject();
            List roles = (List) claims.get("roles");

            return jwtTokenizer.generateAccessToken(email, roles);
        }

        throw new JwtException("token expired");
    }

    private Boolean hasKey(String refreshToken)
    {
        jwtTokenizer.isValidToken(refreshToken);

        Boolean hasKey = redisTemplate.hasKey(refreshToken);
        return hasKey;
    }
}


