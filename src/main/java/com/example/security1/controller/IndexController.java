package com.example.security1.controller;

import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Slf4j
@Controller
@RequiredArgsConstructor
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    //기본 로그인 테스트
    @GetMapping("/test/login")
    public @ResponseBody String testLogin (Authentication authentication
        , @AuthenticationPrincipal PrincipalDetails userDetails) { //DI(의존성 주입)

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal(); //return 타입이 Object //PrincipalDetails 로 다운캐스팅이 가능한 이유는 implement UserDetails 때문
        UserDetails detail = (UserDetails) authentication.getPrincipal();
        log.info("principalDetails : {},{} " , principalDetails.getUser().getId() , principalDetails.getUser().getEmail());
        log.info("detail : {},{} " , detail.getUsername() , detail.getPassword());

        //@AuthenticationPrincipal 통해서 session에 접근가능 (PrincipalDetails == userDetail 같은타입 why? 상속받은것이니까)
        log.info("userDetails : {} " , userDetails.getUsername());
        return "세션정보 확인하기";
    }

    //OAuth 로그인 테스트
    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin (Authentication authentication
            ,@AuthenticationPrincipal OAuth2User oauth) { //DI(의존성 주입)

        //PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal(); 기존 로그인할때 사용할때 oauth에서는 오류가 난다.
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

        //두개 결과값이 같음 => 둘다 쓸수있다
        log.info("oauth authentication : {},{} " , oauth2User.getAttributes());
        log.info("oauth.getAttributes : {} ", oauth.getAttributes());

        return "OAuth 세션정보 확인하기";
    }

    @GetMapping({"","/"})
    public @ResponseBody String index() {
        //머스테치 기본폴더 src/main/resource
        //뷰 리졸버를 설정해주면된다 : templates (prefix), mustache(suffix) 생략가능
        return "index"; //src/main/resource/templates/index.mustache
    }

    //OAuth 로그인해도 Principal , 일반 로그인을 해도 PrincipalDetails 사용가능!
    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails : {} ",principalDetails.getUser().getUsername());

        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    //스프링 시큐리티가 해당주소를 훔쳐감 - SecurityConfig생성하니까 작동을 안함
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinFrom() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        log.info("가입 유저 {}", user);
        user.setRole("user");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data() {
        return "데이터정보";
    }
    private static String getPassword(User user) {
        return user.getPassword();
    }
}

