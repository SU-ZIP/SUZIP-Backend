package Fo.Suzip.domain;

import Fo.Suzip.domain.serviceItem.ServiceItem;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Builder
@Setter
@DynamicUpdate
@DynamicInsert
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Diary extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "diary_id")
    private Long id;

    private String title;

    private String content;

    private String image;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;


    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "diary_emotion_id")
    private DiaryEmotion diaryEmotion;

    @Builder.Default
    @OneToMany(mappedBy = "diary", cascade = CascadeType.ALL)
    private List<ServiceItem> serviceItemList = new ArrayList<>();

    public void setMember(Member member) {
        if (member != null) {
            this.member.getDiaryList().remove(this);
        }
        this.member = member;
    }

    public void addServiceItem(ServiceItem serviceItem) {
        if(!getServiceItemList().contains(serviceItem)){
            getServiceItemList().add(serviceItem);
        }
        serviceItem.setDiary(this);
    }
}
