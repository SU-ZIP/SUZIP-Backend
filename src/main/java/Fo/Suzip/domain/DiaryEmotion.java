package Fo.Suzip.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class DiaryEmotion extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "diary_emotion_id")
    private Long id;

    private String emotion;

    private String color;

    private String content;

    @OneToOne(mappedBy = "diaryEmotion", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Diary diary;
}
