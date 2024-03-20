package Fo.Suzip.web.controller;

import Fo.Suzip.apiPayload.ApiResponse;
import Fo.Suzip.converter.TempConverter;
import Fo.Suzip.service.TempService.TempQueryService;
import Fo.Suzip.web.dto.TempResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/temp")
@RequiredArgsConstructor
public class TestController {

    private final TempQueryService tempQueryService;

    @GetMapping("/test")
    public String test() {
        return "success";
    }

    @GetMapping("/home")
    public ApiResponse<TempResponse.TempTestDTO> home() {

        return ApiResponse.onSuccess(TempConverter.toTempTestDTO());
    }

    @GetMapping("/api")
    public ApiResponse<TempResponse.TempTestDTO> testAPI(){

        return ApiResponse.onSuccess(TempConverter.toTempTestDTO());
    }

    @GetMapping("/exception")
    public ApiResponse<TempResponse.TempExceptionDTO> exceptionAPI(@RequestParam Integer flag){
        tempQueryService.CheckFlag(flag);
        return ApiResponse.onSuccess(TempConverter.toTempExceptionDTO(flag));
    }
}
