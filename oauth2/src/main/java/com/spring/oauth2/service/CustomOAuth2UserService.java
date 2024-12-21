package com.spring.oauth2.service;

import com.spring.oauth2.dto.*;
import com.spring.oauth2.entity.User;
import com.spring.oauth2.repository.UserRepository;
import com.zaxxer.hikari.util.ClockSource;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import javax.swing.text.html.Option;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    // 리소스 서버로부터 받은 유저 정보를 기반으로 로그인을 진행하는 과정
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException{
        System.out.println("load user");
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = switch (registrationId) {
            case "naver"
                    -> new NaverResponse(oAuth2User.getAttributes());
            case "google"
                    -> new GoogleResponse(oAuth2User.getAttributes());
            default
                    -> throw new IllegalArgumentException("Unsupported registrationId: " + registrationId);
        };

        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();

        User user = userRepository.findByUsername(username)
                .map(users -> users.isEmpty() ? null : users.getFirst())
                .orElse(null);

        // 데이터가 존재하지 않는 경우, 유저 데이터를 DB에 입력
        if (user == null){
            User newUser = User.builder()
                    .username(username)
                    .email(oAuth2Response.getEmail())
                    .name(oAuth2Response.getName())
                    .role("ROLE_USER")
                    .build();

            userRepository.save(newUser);
        }

        // 기존 유저 정보 변경
        /*
        else {
            user.setEmail(oAuth2Response.getEmail());
            user.setName(oAuth2Response.getName());

            userRepository.save(user);
        }*/

        // 유저 정보 주입
        UserDTO userDTO = UserDTO.builder()
                .username(username)
                .name(oAuth2Response.getName())
                .role("ROLE_USER")
                .build();

        System.out.println("terminate");
        return new CustomOAuth2User(userDTO);
    }
}
