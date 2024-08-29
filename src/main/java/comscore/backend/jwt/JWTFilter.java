package comscore.backend.jwt;

import comscore.backend.converter.UserConverter;
import comscore.backend.dto.CustomUserDetails;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {
    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        try{
            //request에서 Authorization 헤더를 찾음
            String authorization= request.getHeader("Authorization");

            //Authorization 헤더 검증
            if (authorization == null || !authorization.startsWith("Bearer ")) {

                System.out.println("token null");
                filterChain.doFilter(request, response);

                //조건이 해당되면 메소드 종료 (필수)
                return;
            }
            System.out.println("authorization now");
            //Bearer 부분 제거 후 순수 토큰만 획득
            String token = authorization.split(" ")[1];
            //띄어쓰기를 기준으로 뒷 부분이 인덱스 1이니까 그 부분만 가져옴

            //토큰 소멸 시간 검증
            if (jwtUtil.isExpired(token)) {

                System.out.println("token expired");
                filterChain.doFilter(request, response);

                //조건이 해당되면 메소드 종료 (필수)
                return;
            }
            //여기부터 세션을 만들어서 유저의 일시적인 세션을 만들어 저장하여 세션을 요청하는 곳에 전달 가능
            //토큰에서 username과 role 획득
            String username = jwtUtil.getUsername(token);
            String role = jwtUtil.getRole(token);

            //UserDetails에 회원 정보 객체 담기. DB 조회해서 진짜 비번을 넣으면 계속 db를 조회하고 성능이 안 좋아서 그냥 임의의 값을 넣어도 됨.
            CustomUserDetails customUserDetails = new CustomUserDetails(UserConverter.toUser(username, "temppwd", "tempNick", role));

            //스프링 시큐리티 인증 토큰 생성
            Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
            //세션에 사용자 등록
            SecurityContextHolder.getContext().setAuthentication(authToken);
        } catch (ExpiredJwtException e){
            // 만료된 토큰 예외 처리
            System.out.println("Token is expired: " + e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Token has expired");
            return; // 조건이 해당되면 메소드 종료 (필수)
        } catch (Exception e) {
            // 기타 예외 처리
            System.out.println("Error occurred during token processing: " + e.getMessage());
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("An error occurred while processing the token");
            return;
        }
        System.out.println("authorization is = what?");
        filterChain.doFilter(request, response);
        //그 다음 필터로 넘겨줘
    }
}
