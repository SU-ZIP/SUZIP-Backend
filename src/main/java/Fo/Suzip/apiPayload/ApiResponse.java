package Fo.Suzip.apiPayload;

import Fo.Suzip.apiPayload.code.BaseCode;
import Fo.Suzip.apiPayload.code.status.ErrorStatus;
import Fo.Suzip.apiPayload.code.status.SuccessStatus;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.HashMap;
import java.util.Map;

//@Getter
//@AllArgsConstructor
//@JsonPropertyOrder({"isSuccess", "code", "message", "result"})
//public class ApiResponse<T> {
//
//    @JsonProperty("isSuccess")
//    private final Boolean isSuccess;
//    private final String code;
//    private final String message;
//    @JsonInclude(JsonInclude.Include.NON_NULL)
//    private T result;
//
//
//    // 성공한 경우 응답 생성
//
//    public static <T> ApiResponse<T> onSuccess(T result){
//        return new ApiResponse<>(true, SuccessStatus._OK.getCode() , SuccessStatus._OK.getMessage(), result);
//    }
//
//    public static <T> ApiResponse<T> of(BaseCode code, T result){
//            return new ApiResponse<>(true, code.getReasonHttpStatus().getCode() , code.getReasonHttpStatus().getMessage(), result);
//    }
//
//
//    // 실패한 경우 응답 생성
//    public static <T> ApiResponse<T> onFailure(String code, String message, T data){
//        return new ApiResponse<>(false, code, message, data);
//    }

@Getter
@RequiredArgsConstructor
@AllArgsConstructor
@JsonPropertyOrder({"isSuccess", "code", "message", "result"})
public class ApiResponse<T> {

    @JsonProperty("isSuccess")
    private final Boolean isSuccess;
    private final String code;
    private final String message;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private T result;


    public static <T> ApiResponse<T> onSuccess(T result){
        return new ApiResponse<>(true, SuccessStatus._OK.getCode() , SuccessStatus._OK.getMessage(), result);
    }

    public static <T> ApiResponse<T> of(BaseCode code, T result){
        return new ApiResponse<>(true, code.getReasonHttpStatus().getCode() , code.getReasonHttpStatus().getMessage(), result);
    }


    // 실패한 경우 응답 생성
    public static <T> ApiResponse<T> onFailure(String code, String message, T data){
        return new ApiResponse<>(false, code, message, data);
    }

    public static <T> ApiResponse<T> invalidAccessToken() {
        return new ApiResponse(false, ErrorStatus._INVALID_ACCESS_TOKEN.getCode(), ErrorStatus._INVALID_ACCESS_TOKEN.getMessage(), null);
    }

    public static <T> ApiResponse<T> invalidRefreshToken() {
        return new ApiResponse(false, ErrorStatus._INVALID_REFRESH_TOKEN.getCode(), ErrorStatus._INVALID_REFRESH_TOKEN.getMessage(), null);
    }

    public static <T> ApiResponse<T> notExpiredTokenYet() {
        return new ApiResponse(false, ErrorStatus._NOT_EXPIRED_TOKEN_YET.getCode(), ErrorStatus._NOT_EXPIRED_TOKEN_YET.getMessage(), null);
    }


}
