package comscore.backend.service;

import comscore.backend.converter.UserConverter;
import comscore.backend.domain.User;
import comscore.backend.dto.JoinRequestDTO;
import comscore.backend.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class JoinService {
    private UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinRequestDTO joinRequestDTO) {
        String username = joinRequestDTO.getEmail();
        String password = joinRequestDTO.getPassword();
        String nickName = joinRequestDTO.getNickName();

        User user = userRepository.findByEmail(username);
        if (user != null) {//중복회원
            throw new IllegalArgumentException("이미 존재하는 이메일입니다.");
        }

        userRepository.save(UserConverter.toUser(username, bCryptPasswordEncoder.encode(password), nickName, "ADMIN"));
    }
}
