package Fo.Suzip.domain;

import jakarta.persistence.*;
import lombok.*;

@Getter
@Builder
@Setter
@Entity
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    private String username;

    private String name;

    private String email;

    private String role;

    public User() {

    }
}


