package stirling.software.spdf.enterprise.config.security.sso;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.SavedRequest;
import stirling.software.spdf.enterprise.util.RequestUriUtil;

@Slf4j
@ConditionalOnProperty(
        value = "stirling-pdf.enterprise-edition.enabled",
        havingValue = "true")
public class Saml2AuthenticationSuccessHandler
        extends SavedRequestAwareAuthenticationSuccessHandler {

    public static final String SPRING_SECURITY_SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";

    @Value("${stirling-pdf.enterprise-edition.sso.auto-create-user:false}")
    private boolean autoCreateUser;

    @Value("${stirling-pdf.enterprise-edition.sso.block-registration:false}")
    private boolean isRegistrationBlocked;

//    private LoginAttemptService loginAttemptService;
//    private ApplicationProperties applicationProperties;
//    private UserService userService;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws ServletException, IOException {

        Object principal = authentication.getPrincipal();
        log.debug("Starting SAML2 authentication success handling");

        if (principal instanceof CustomSaml2AuthenticatedPrincipal saml2Principal) {
            String username = saml2Principal.name();
            log.debug("Authenticated principal found for user: {}", username);

            HttpSession session = request.getSession(false);
            String contextPath = request.getContextPath();
            SavedRequest savedRequest =
                    (session != null)
                            ? (SavedRequest) session.getAttribute(SPRING_SECURITY_SAVED_REQUEST)
                            : null;

            log.debug(
                    "Session exists: {}, Saved request exists: {}",
                    session != null,
                    savedRequest != null);

            if (savedRequest != null
                    && !RequestUriUtil.isStaticResource(
                            contextPath, savedRequest.getRedirectUrl())) {
                log.debug(
                        "Valid saved request found, redirecting to original destination: {}",
                        savedRequest.getRedirectUrl());
                super.onAuthenticationSuccess(request, response, authentication);
            } else {
                log.debug(
                        "Processing SAML2 authentication with autoCreateUser: {}", autoCreateUser);

                // todo: figure out where LoginAttemptService should live
//                if (loginAttemptService.isBlocked(username)) {
//                    log.debug("User {} is blocked due to too many login attempts", username);
//
//                    if (session != null) {
//                        session.removeAttribute(SPRING_SECURITY_SAVED_REQUEST);
//                    }
//                    throw new LockedException(
//                            "Your account has been locked due to too many failed login attempts.");
//                }
//
//                boolean userExists = userService.usernameExistsIgnoreCase(username);
//                boolean hasPassword = userExists && userService.hasPassword(username);
//                boolean isSSOUser =
//                        userExists
//                                && userService.isAuthenticationTypeByUsername(
//                                        username, AuthenticationType.SSO);

//                log.debug(
//                        "User status - Exists: {}, Has password: {}, Is SSO user: {}",
//                        userExists,
//                        hasPassword,
//                        isSSOUser);
//
//                if (userExists && hasPassword && !isSSOUser && autoCreateUser) {
//                    log.debug(
//                            "User {} exists with password but is not SSO user, redirecting to logout",
//                            username);
//                    response.sendRedirect(
//                            contextPath + "/logout?oAuth2AuthenticationErrorWeb=true");
//                    return;
//                }

                try {
//                    if (isRegistrationBlocked && !userExists) {
//                        log.debug("Registration blocked for new user: {}", username);
//                        response.sendRedirect(
//                                contextPath + "/login?errorOAuth=oAuth2AdminBlockedUser");
//                        return;
//                    }
                    log.debug("Processing SSO post-login for user: {}", username);
//                    userService.processSSOPostLogin(username, autoCreateUser);
                    log.debug("Successfully processed authentication for user: {}", username);
                    response.sendRedirect(contextPath + "/");
                } catch (IllegalArgumentException e) {
                    log.debug(
                            "Invalid username detected for user: {}, redirecting to logout",
                            username);
                    response.sendRedirect(contextPath + "/logout?invalidUsername=true");
                }
            }
        } else {
            log.debug("Non-SAML 2 principal detected, delegating to parent handler");
            super.onAuthenticationSuccess(request, response, authentication);
        }
    }
}
