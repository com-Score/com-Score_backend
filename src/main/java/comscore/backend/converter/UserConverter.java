package comscore.backend.converter;

import comscore.backend.domain.User;

public class UserConverter {
    public static User toUser(String email, String password, String nickName, String role){
        return User.builder()
                .email(email)
                .password(password)
                .nickName(nickName)
                .role(role)
                .build();
    }
}
