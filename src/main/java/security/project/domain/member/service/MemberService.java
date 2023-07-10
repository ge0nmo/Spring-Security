package security.project.domain.member.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import security.project.domain.member.entity.Member;
import security.project.domain.member.repository.MemberRepository;
import security.project.global.security.utils.CustomAuthorityUtils;

import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Transactional
@Service
public class MemberService
{
    private final MemberRepository memberRepository;

    private final PasswordEncoder passwordEncoder;
    private final CustomAuthorityUtils authorityUtils;

    public Member createMember(Member member)
    {
        verifyEmail(member.getEmail());

        String encodedPassword = passwordEncoder.encode(member.getPassword());
        member.setPassword(encodedPassword);

        List<String> roles = authorityUtils.createRoles(member.getEmail());
        member.setRoles(roles);

        return memberRepository.save(member);
    }

    @Transactional(readOnly = true)
    public Member getMember(Long id)
    {
        return memberRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Member Not Found"));
    }

    public void deleteMember(Long memberId)
    {
        verifyExistMember(memberId);

        memberRepository.deleteById(memberId);
    }

    private void verifyEmail(String email)
    {
        Optional<Member> optionalMember = memberRepository.findByEmail(email);

        if(optionalMember.isPresent())
            throw new RuntimeException("Email is already used");
    }

    public void verifyExistMember(Long id)
    {
        memberRepository.findById(id).orElseThrow(() -> new UsernameNotFoundException("user not found"));
    }
}
