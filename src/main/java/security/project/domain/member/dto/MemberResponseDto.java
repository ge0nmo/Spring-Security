package security.project.domain.member.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Getter
@Builder
@AllArgsConstructor
public class MemberResponseDto
{
    private Long memberId;

    private String email;

    private String password;

    private String nickname;
    private List<String> roles = new ArrayList<>();

    private int age;

    private LocalDateTime createdAt;

}
