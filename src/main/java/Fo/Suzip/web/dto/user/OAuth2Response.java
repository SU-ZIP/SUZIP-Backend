package Fo.Suzip.web.dto.user;

public interface OAuth2Response {
    String getProvider();

    String getProviderId();

    String getEmail();

    String getName();
}