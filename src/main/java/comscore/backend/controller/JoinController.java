package comscore.backend.controller;

import comscore.backend.dto.JoinRequestDTO;
import comscore.backend.global.response.ApiResponse;
import comscore.backend.service.JoinService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class JoinController {
    private JoinService joinService;

    @PostMapping("/join")
    public ApiResponse<String> joinProcess(@RequestBody JoinRequestDTO joinRequestDTO) {
        joinService.joinProcess(joinRequestDTO);
        return ApiResponse.ok("회원 가입 완료", "");
    }
}
