package security.project.global.security.userdetails;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import security.project.domain.member.entity.Member;
import security.project.domain.member.repository.MemberRepository;
import security.project.global.security.utils.CustomAuthorityUtils;

import java.util.Collection;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Component
public class MemberDetailsService implements UserDetailsService
{
    private final MemberRepository memberRepository;
    private final CustomAuthorityUtils authorityUtils;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        Optional<Member> optionalMember = memberRepository.findByEmail(username);

        Member findMember = optionalMember.orElseThrow(() -> new UsernameNotFoundException("Member Not Exist"));

        return new MemberDetails(findMember);
    }

    private final class MemberDetails extends Member implements UserDetails
    {
        MemberDetails(Member member)
        {
            setMemberId(member.getMemberId());
            setEmail(member.getEmail());
            setPassword(member.getPassword());
            setRoles(member.getRoles());
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities()
        {
            log.info("===getAuthorities===");
            log.info("roles = {}", this.getRoles());

            return authorityUtils.createAuthorities(this.getRoles());
        }

        @Override
        public String getUsername()
        {
            return getEmail();
        }

        @Override
        public boolean isAccountNonExpired()
        {
            return true;
        }

        @Override
        public boolean isAccountNonLocked()
        {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired()
        {
            return true;
        }

        @Override
        public boolean isEnabled()
        {
            return true;
        }
    }
}
