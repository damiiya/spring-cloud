package com.welab.backend_user.domain.dto;

import com.welab.backend_user.domain.SiteUser;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SiteUserRegisterDto {
    @NotBlank(message = "아이디를 입력하세요.")
    private String userId;

    @NotBlank(message = "비밀번호를 입력하세요.")
    private String password;

    @NotBlank(message = "전화번호를 입력하세요.")
    private String phoneNumber;

    public SiteUser toEntity() {
        SiteUser siteUser = new SiteUser();

        siteUser.setUserId(this.userId);
        siteUser.setPhoneNumber(this.phoneNumber);

        /*
        * SHA1 || SHA256 으로 password를 해시 값으로 변환
        * 1. 나의 방법: util -> PasswordUtil에 encryptSHA256을 만들어서 변환
        * String hashPassword = PasswordUtil.encryptSHA256(this.password);
        * 2. Spring Security의 BCryptPasswordEncoder를 사용하는게 보안상 더 좋음
        *    이 방법은 bean 주입 방식이기 때문에 dto에서 사용하지 않고 service계층에서 암호화 수행함
        * */
        String hashPassword = this.password;
        siteUser.setPassword(hashPassword);

        return siteUser;
    }
}
