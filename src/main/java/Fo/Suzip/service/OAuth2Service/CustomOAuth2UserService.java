package Fo.Suzip.service.OAuth2Service;

import Fo.Suzip.domain.Member;
import Fo.Suzip.repository.MemberRepository;
import Fo.Suzip.web.dto.*;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {


    private final MemberRepository memberRepository;

    public CustomOAuth2UserService(MemberRepository memberRepository) {

        this.memberRepository = memberRepository;
    }
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println(oAuth2User);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;
        if (registrationId.equals("naver")) {

            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        }
        else if (registrationId.equals("google")) {

            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        }
        else {

            return null;
        }

        //리소스 서버에서 발급 받은 정보로 사용자를 특정할 아이디값을 만듬
        String username = oAuth2Response.getProvider()+" "+oAuth2Response.getProviderId();

        Member existData = memberRepository.findByName(username);

        if (existData == null) {

            Member member = Member.builder()
                    .name(oAuth2Response.getName())
                    .email(oAuth2Response.getEmail())
                    // .role("ROLE_USER") // 필요하다면 builder 패턴으로 role 설정
                    .build();
            //member.setRole("ROLE_USER");

            memberRepository.save(member);

            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(username);
            userDTO.setName(oAuth2Response.getName());
            //userDTO.setRole("ROLE_USER");

            return new CustomOAuth2User(userDTO);
        }
        else {

            existData.setEmail(oAuth2Response.getEmail());
            existData.setName(oAuth2Response.getName());

            memberRepository.save(existData);

            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(existData.getName());
            userDTO.setName(oAuth2Response.getName());
            //userDTO.setRole(existData.getRole());

            return new CustomOAuth2User(userDTO);
        }
    }
}