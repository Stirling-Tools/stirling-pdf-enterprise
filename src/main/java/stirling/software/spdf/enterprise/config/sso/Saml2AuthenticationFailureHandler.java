package stirling.software.spdf.enterprise.config.sso;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

@Slf4j
@ConditionalOnProperty(value = "stirling-pdf.enterprise-edition.enabled", havingValue = "true")
public class Saml2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException {
        log.error("Error during SAML 2 authentication");

        if (exception instanceof Saml2AuthenticationException) {
            Saml2Error error = ((Saml2AuthenticationException) exception).getSaml2Error();

            log.error("Error Code: {}, Description: {}", error.getErrorCode(), error.getDescription());

            getRedirectStrategy()
                    .sendRedirect(request, response, "/login?errorSaml=" + error.getErrorCode());
        } else if (exception instanceof ProviderNotFoundException) {
            log.error(exception.getLocalizedMessage());
            getRedirectStrategy()
                    .sendRedirect(
                            request,
                            response,
                            "/login?errorSaml=no_authentication_provider_found");
        } else {
            log.error(exception.getLocalizedMessage());
            getRedirectStrategy().sendRedirect(request, response, "/login?errorSaml");
        }
    }
}
