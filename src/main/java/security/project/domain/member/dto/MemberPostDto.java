package security.project.domain.member.dto;

import lombok.Getter;

@Getter
public class MemberPostDto
{
    private String email;

    private String password;

    private String nickname;

    private int age;
}
