package Fo.Suzip.web.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Getter
@NoArgsConstructor
//@AllArgsConstructor
public class DiaryRequestDTO {

    @Builder
    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CreateRequestDTO {  //일기 생성 요청 DTO
        private String title; //일기 제목
        private String content; //일기 내용
        private Long memberId; // 이용자 ID
        private LocalDate date; // 일기 날짜
}

    @Builder
    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UpdateRequestDTO { //일기 수정 요청 DTO
        //private Long diaryId; // 일기 ID
        private String title; // 일기 제목
        private String content; // 일기 내용
        private LocalDate date; // 갱신할 일기 날짜
    }

    @Builder
    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SearchRequestDTO { //일기 검색 요청 DTO
        private String title; // 검색할 제목
        private String emotion; // 검색할 감정
        private LocalDate startDate; // 검색할 시작 날짜
        private LocalDate endDate; // 검색할 종료 날짜
    }
}
