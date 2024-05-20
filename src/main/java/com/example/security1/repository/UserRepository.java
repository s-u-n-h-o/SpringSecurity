package com.example.security1.repository;

import com.example.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

//CRUD 함수를 JpaRepository가 들고있음
//@Repository라는 어노테이션이 없어도 IoC된다 -> JpaRepository를 상속했기때문
public interface UserRepository extends JpaRepository<User, Integer> {

    //findBy 규칙 -> Username문법
    //select * from user where username =? 과 같은것
    public User findByUsername(String username); //Jpa query method 공부하기
}