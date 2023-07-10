package security.project.domain.member.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import security.project.domain.member.dto.MemberPostDto;
import security.project.domain.member.dto.MemberResponseDto;
import security.project.domain.member.entity.Member;
import security.project.domain.member.mapper.MemberMapper;
import security.project.domain.member.service.MemberService;

import javax.validation.constraints.Positive;

@Slf4j
@Validated
@RequiredArgsConstructor
@RequestMapping("/members")
@RestController
public class MemberController
{
    private final MemberService memberService;

    private final MemberMapper mapper;
    @PostMapping
    public ResponseEntity postMember(@RequestBody MemberPostDto memberPostDto)
    {
        Member member = memberService.createMember(mapper.postToMember(memberPostDto));

        MemberResponseDto response = mapper.memberToResponse(member);

        log.info("member created");
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @GetMapping("/{member-id}")
    public ResponseEntity getMember(@PathVariable("member-id")@Positive Long memberId)
    {
        Member member = memberService.getMember(memberId);

        MemberResponseDto response = mapper.memberToResponse(member);

        return new ResponseEntity(response, HttpStatus.OK);
    }

    @DeleteMapping("/{member-id}")
    public ResponseEntity deleteMember(@PathVariable("member-id") @Positive Long memberId)
    {
        memberService.deleteMember(memberId);

        return new ResponseEntity(HttpStatus.NO_CONTENT);
    }
}
