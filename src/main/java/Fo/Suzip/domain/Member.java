package Fo.Suzip.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Builder
@Setter
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    private String name;

    private String nickName;

    private String profileImage;

    private String email;

    @Enumerated(EnumType.STRING)
    private Gender gender;

    private LocalDate birthDay;

    @Builder.Default
    @OneToMany(mappedBy = "member", cascade = CascadeType.ALL)
    private List<Diary> diaryList = new ArrayList<>();

    @Builder.Default
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
}
