package security.project.domain.member.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@AllArgsConstructor
public class MemberResponseDto
{
    private Long id;

    private String email;

    private String password;

    private String nickname;

    private int age;

}
