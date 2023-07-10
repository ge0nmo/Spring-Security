package security.project.global.security.auth.repository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;
import security.project.global.security.jwt.JwtTokenizer;

import java.util.concurrent.TimeUnit;

@Slf4j
@RequiredArgsConstructor
@Repository
public class RedisRepository
{
    private final JwtTokenizer jwtTokenizer;
    private final RedisTemplate<String, String> redisTemplate;

    public void saveRefreshToken(String refreshToken, String email)
    {
        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();

        valueOperations.set(refreshToken, email, jwtTokenizer.getRefreshTokenExpirationMinutes(), TimeUnit.MINUTES);
        log.info("refreshToken saved in the redis db = {}", refreshToken);
    }

    public void deleteRefreshToken(String refreshToken)
    {
        redisTemplate.delete(refreshToken);
        log.info("refreshToken deleted from the redis db = {}", refreshToken);
    }

}
