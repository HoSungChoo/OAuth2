package com.spring.oauth2.service;

import com.spring.oauth2.dto.*;
import com.spring.oauth2.entity.User;
import com.spring.oauth2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import javax.swing.text.html.Option;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    // 리소스 서버로부터 받은 유저 정보를 기반으로 로그인을 진행하는 과정
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException{
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println(oAuth2User);

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
        User user = userRepository.findByUsername(username);

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

        else {
            user.setEmail(oAuth2Response.getEmail());
            user.setName(oAuth2Response.getName());

            userRepository.save(user);
        }

        // 유저 정보 주입
        UserDTO userDTO = UserDTO.builder()
                .username(username)
                .name(oAuth2Response.getName())
                .role("ROLE_USER")
                .build();

        return new CustomOAuth2User(userDTO);
    }
}
