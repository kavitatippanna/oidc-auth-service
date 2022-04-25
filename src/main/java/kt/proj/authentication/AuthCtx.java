package kt.proj.authentication;

import java.net.URI;

public class AuthCtx {
    public static final String COOKIE_VALUE_SEPARATOR = ":";
    private URI redirectUrl;
    private String state;
    private String provider;

    public URI getRedirectUrl() {
        return redirectUrl;
    }

    public void setRedirectUrl(URI redirectUrl) {
        this.redirectUrl = redirectUrl;
    }
    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }
}
