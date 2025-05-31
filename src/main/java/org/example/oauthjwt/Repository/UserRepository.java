package org.example.oauthjwt.Repository;

import org.example.oauthjwt.Entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    // 사용자 이름으로 UserEntity를 찾는 메소드
    UserEntity findByUsername(String username);
}
