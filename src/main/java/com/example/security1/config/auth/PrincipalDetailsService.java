package com.example.security1.config.auth;

import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

// 시큐리티 설정에서(SecurityConfig) loginProcessingUrl("/login");
// /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어있는 loadUserByUsernaem 함수가 실행
// *implements UserDetailsService 이 타입으로 꼭 만들어놔야지 loadUserByUsername함수가 호출된다
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    //시큐리티 session(내부 Authentication(내부 UserDetails))
    //함수종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {//String username : 로그인페이지의 name값 username명칭으로 받아와야함
        User userEntity = userRepository.findByUsername(username);
        Optional<User> userOptional = Optional.ofNullable(userEntity);

//         optional과 같은것
//        if(userEntity != null) {
//            return new PrincipalDetails(userEntity);
//        }

        return userOptional.map(PrincipalDetails::new).orElse(null);
    }
}
