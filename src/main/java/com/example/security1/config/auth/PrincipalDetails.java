package com.example.security1.config.auth;

//시큐리티가 /Login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
//로그인을 진행이 완료가 되면 시큐리티 session을 만들어준다. (Security ContextHolder)
//오브젝트 => Authentication 타입 객체
//Authentication 안에 User정보가 있어야된다.
//User 오브젝트 타입 => UserDetails 타입객체다.

//Security Session => Authentication => UserDetails

import com.example.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Data
public class PrincipalDetails implements UserDetails , OAuth2User {

    private User user;//콤포지션
    private Map<String, Object> attributes;

    //일반 로그인할때 생성하는 생성자
    public PrincipalDetails(User user) {
        this.user = user;
    }

    //OAuth로그인 할때 생성되는 생성자
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes =attributes;
    }

    @Override
    public <A> A getAttribute(String name) {
        return OAuth2User.super.getAttribute(name);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return null;
    }

    @Override
    public String getName() {
        return null;
    }

    //해당 User의 권한을 리턴하는곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() { //계정이 만료되었니?
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() { //비번 기간이 지났니?
        return true;
    }

    @Override
    public boolean isEnabled() {
        //우리의 사이트에서 1년동안 회원이 로그인을 안하면, 휴면계정으로 하기로함
        //현재시간 - 로그인시간 = 일년 초과시 return false로 줄때 사용

        return true;
    }
}
