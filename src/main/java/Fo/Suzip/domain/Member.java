package Fo.Suzip.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    private String name;

    private String userName;

    private String profileImage;

    private String email;

    private String password;

    private String userRole;

    private String provider;

    @Setter
    private String refreshToken;

    @Enumerated(EnumType.STRING)
    private Gender gender;

    private LocalDate birthDay;


    @OneToMany(mappedBy = "member", cascade = CascadeType.ALL)
    private List<Diary> diaryList = new ArrayList<>();

    @OneToMany(mappedBy = "member", cascade = CascadeType.ALL)
    private List<MemberItem> memberItemList = new ArrayList<>();

    public void addDiary(Diary diary) {
        if(!getDiaryList().contains(diary)){
            getDiaryList().add(diary);
        }
        diary.setMember(this);
    }

    public void removeDiary(Diary diary) {
        this.getDiaryList().remove(diary);
        diary.setMember(null);
    }

    public void addMemberItem(MemberItem memberItem) {
        if (!getMemberItemList().contains(memberItem)) {
            getMemberItemList().add(memberItem);
        }
        memberItem.setMember(this);
    }

    public void removeMemberItem(MemberItem memberItem) {
        this.getMemberItemList().remove(memberItem);
        memberItem.setMember(null);
    }

    public void updateEmail(String email) {
        this.email = email;
    }

    public void updateName(String name) {
        this.name = name;
    }
}
