package Fo.Suzip.web.controller;

import Fo.Suzip.web.dto.MemberRequestDTO;
import Fo.Suzip.web.dto.MemberResponseDTO;
import io.jsonwebtoken.io.IOException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {
//
//    private final RefreshTokenRepository tokenRepository;
//    private final RefreshTokenService tokenService;
//    private final JwtUtil jwtUtil;
//    private final EmitterRepository emitterRepository;
//

//    @PostMapping("/signup")
//    public ApiResponse<MemberResponseDTO.JoinResultDto> join(@RequestBody @Valid MemberRequestDTO.JoinDto request)  {
//
//        Member response = memberService.signup(request, url);
//        log.info(request.getName(), file);
//
//        return ApiResponse.onSuccess(MemberConverter.toJoinResult(response, jwtProvider));
//    }

//    @PostMapping("token/logout")
//    public ResponseEntity<StatusResponseDto> logout(@RequestHeader("Authorization") final String accessToken) {
//
//        // 엑세스 토큰으로 현재 Redis 정보 삭제
//        tokenService.removeRefreshToken(accessToken);
//        return ResponseEntity.ok(StatusResponseDto.addStatus(200));
//    }
//
//    @PostMapping("/token/refresh")
//    public ResponseEntity<TokenResponseStatus> refresh(@RequestHeader("Authorization") final String accessToken) {
//
//        // 액세스 토큰으로 Refresh 토큰 객체를 조회
//        Optional<RefreshToken> refreshToken = tokenRepository.findByAccessToken(accessToken);
//
//        // RefreshToken이 존재하고 유효하다면 실행
//        if (refreshToken.isPresent() && jwtUtil.verifyToken(refreshToken.get().getRefreshToken())) {
//            // RefreshToken 객체를 꺼내온다.
//            RefreshToken resultToken = refreshToken.get();
//            // 권한과 아이디를 추출해 새로운 액세스토큰을 만든다.
//            String newAccessToken = jwtUtil.generateAccessToken(resultToken.getId(), jwtUtil.getRole(resultToken.getRefreshToken()));
//            // 액세스 토큰의 값을 수정해준다.
//            resultToken.updateAccessToken(newAccessToken);
//            tokenRepository.save(resultToken);
//            // 새로운 액세스 토큰을 반환해준다.
//            return ResponseEntity.ok(TokenResponseStatus.addStatus(200, newAccessToken));
//        }
//
//        return ResponseEntity.badRequest().body(TokenResponseStatus.addStatus(400, null));
//    }

}