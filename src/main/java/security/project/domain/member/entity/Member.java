package security.project.domain.member.entity;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import security.project.global.audit.BaseEntity;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Entity
public class Member extends BaseEntity
{
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long memberId;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false, length = 100)
    private String password;

    @Column(nullable = false, unique = true)
    private String nickname;

    @Column(nullable = false)
    private int age;

    @ElementCollection(fetch = FetchType.EAGER)
    private List<String> roles = new ArrayList<>();

    @Builder
    public Member(String email, String password, String nickname, int age)
    {
        this.email = email;
        this.password = password;
        this.nickname = nickname;
        this.age = age;
    }


    //=============회원 정보 수정=============//
    public void changeNickname(String nickname)
    {
        this.nickname = nickname;
    }

    public void changeAge(int age)
    {
        this.age = age;
    }


    //=============Security=============//
    public void setMemberId(Long memberId)
    {
        this.memberId = memberId;
    }

    public void setEmail(String email)
    {
        this.email = email;
    }

    public void setPassword(String password)
    {
        this.password = password;
    }

    public void setRoles(List<String> roles)
    {
        this.roles = roles;
    }
}
