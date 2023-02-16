package security.project.domain.member.mapper;

import org.mapstruct.Mapper;
import org.springframework.stereotype.Component;
import security.project.domain.member.dto.MemberPostDto;
import security.project.domain.member.dto.MemberResponseDto;
import security.project.domain.member.entity.Member;

@Component
public class MemberMapper
{
    public Member postToMember(MemberPostDto request)
    {
        if(request == null)
            return null;

        Member member = Member.builder()
                .email(request.getEmail())
                .password(request.getPassword())
                .nickname(request.getNickname())
                .age(request.getAge())
                .build();

        return member;
    }

    public MemberResponseDto memberToResponse(Member entity)
    {
        if(entity == null)
            return null;

        MemberResponseDto response = MemberResponseDto.builder()
                .memberId(entity.getMemberId())
                .email(entity.getEmail())
                .password(entity.getPassword())
                .nickname(entity.getNickname())
                .age(entity.getAge())
                .createdAt(entity.getCreatedAt())
                .build();

        return response;
    }
}
