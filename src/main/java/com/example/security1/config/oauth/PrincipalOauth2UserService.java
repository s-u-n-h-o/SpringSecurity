package com.example.security1.config.oauth;

import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    
    @Autowired
    private UserRepository userRepository;

    //구글로 부터 받은 userRequest데이터에대한 후처리되는 함수
    //함수종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        log.info("getClientRegistration : {} " , userRequest.getClientRegistration()); //registrationid로 어떤 OAuth로 로그인했는지 확인가능
        log.info("getAccessToken : {} " , userRequest.getAccessToken().getTokenValue());

        OAuth2User oauth2User = super.loadUser(userRequest);
        //구글 로그인버튼 클릭 -> 구글 로그인창 -> 로그인 완료 -> code를 리턴(OAuth-Client 라이브러리) -> AccessToken요청
        //userRequest 정보 -> loadUser함수 호출 -> 구글로 부터 회원프로필을 받아준다.
        log.info("getAttributes : {} " , oauth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getClientId();//Google
        String providerId = oauth2User.getAttribute("sub");//Google의 id값
        String username = provider + "_" + providerId; // google_~~~
        String password = bCryptPasswordEncoder.encode("겟데이"); //그냥 해봄
        String email = oauth2User.getAttribute("email");
        String role = "ROLE_USER";
        
        //이미 존재하는 회원인지 확인후 회원가입
        User userEntity = userRepository.findByUsername(username);
        if(userEntity == null) {
            userEntity= User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }

        //PrincipalDetails(userEntity, oauth2User.getAttributes()); 이게 생성되면 Authentication으로 들어간다
        return new PrincipalDetails(userEntity, oauth2User.getAttributes());
    }
}
