package org.example.oauthjwt.Service;

import org.example.oauthjwt.Dto.*;
;
import org.example.oauthjwt.Entity.UserEntity;
import org.example.oauthjwt.Repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    // 이 클래스는 OAuth2 사용자 정보를 가져오는 데 사용됩니다.
    // 필요한 경우 사용자 정보를 처리하는 로직을 추가할 수 있습니다.

    // 예를 들어, 사용자 정보를 데이터베이스에 저장하거나,
    // 특정 필드를 변환하는 등의 작업을 수행할 수 있습니다.

    // 현재는 기본 기능만 사용하고 있으므로 추가적인 구현은 없습니다.

    // 만약 사용자 정보를 처리하는 로직이 필요하다면,
    // loadUser 메서드를 오버라이드하여 사용자 정보를 처리할 수 있습니다.

    private UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 기본 사용자 정보 로드
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println(oAuth2User);

        // 여기서 oAuth2User를 처리하는 로직을 추가할 수 있습니다.
        // 예를 들어, 사용자 정보를 데이터베이스에 저장하거나,
        // 특정 필드를 변환하는 등의 작업을 수행할 수 있습니다.
        // registrationId를 사용하여 특정 OAuth2 제공자에 대한 사용자 정보를 처리할 수 있습니다.

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;

        if (registrationId.equals("naver")) {
            // 네이버 OAuth2 사용자 정보 처리 로직
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        } else if (registrationId.equals("kakao")) {
            // 카카오 OAuth2 사용자 정보 처리 로직
            // oAuth2Response = new OAuth2Response(oAuth2User.getAttributes());
        } else if (registrationId.equals("google")) {
            // 구글 OAuth2 사용자 정보 처리 로직
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        }
        else {
            return null;
        }

        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();
        UserEntity existData = userRepository.findByUsername(username);

        // 사용자 정보가 데이터베이스에 존재하는지 확인
        // 존재하지 않는 경우 새 사용자 생성 로직을 추가.
        if (existData == null) {
            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setEmail(oAuth2Response.getEmail());
            userEntity.setName(oAuth2Response.getName());
            userEntity.setRole("ROLE_USER");

            // 사용자 정보를 데이터베이스에 저장
            userRepository.save(userEntity);

            UserDto userDto = new UserDto();
            userDto.setUsername(username);
            userDto.setRole("ROLE_USER");
            userDto.setName(oAuth2Response.getName());

            return new CustomOAuth2User(userDto);
        }
        else {
            // 이미 존재하는 사용자 정보가 있다면, 해당 정보 업데이트.
            existData.setUsername(username);
            existData.setEmail(oAuth2Response.getEmail());
            existData.setName(oAuth2Response.getName());
            existData.setRole("ROLE_USER");

            userRepository.save(existData);

            UserDto userDto = new UserDto();
            userDto.setUsername(username);
            userDto.setRole("ROLE_USER");
            userDto.setName(oAuth2Response.getName());

            return new CustomOAuth2User(userDto);
        }
    }
}