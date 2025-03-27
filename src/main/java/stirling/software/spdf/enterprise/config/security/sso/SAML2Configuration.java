package stirling.software.spdf.enterprise.config.security.sso;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.HttpSessionSaml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml5AuthenticationRequestResolver;
import stirling.software.SPDF.config.security.SAML2ConfigurationInterface;
import stirling.software.spdf.enterprise.util.CertificateUtil;

@Slf4j
@Configuration
@ConditionalOnProperty(value = "stirling-pdf.enterprise-edition.enabled", havingValue = "true")
public class SAML2Configuration implements SAML2ConfigurationInterface {

    private static final String REGISTRATION_ID = "stirling-pdf";

    @Autowired
    private Saml2RelyingPartyProperties saml2Properties;

    @Bean
    @Override
    public OpenSaml5AuthenticationProvider authenticationProvider() {
        OpenSaml5AuthenticationProvider authenticationProvider = new OpenSaml5AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(new Saml2ResponseAuthenticationConverter());

        return authenticationProvider;
    }

    @Bean
    @Override
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() {
        Saml2RelyingPartyProperties.Registration registration = saml2Properties.getRegistration().get(REGISTRATION_ID);
        RelyingPartyRegistration.Builder relyingPartyRegistrationBuilder;

        if (registration.getAssertingparty().getMetadataUri() != null) {
            relyingPartyRegistrationBuilder = RelyingPartyRegistrations.fromMetadataLocation(registration.getAssertingparty().getMetadataUri())
                    .registrationId(REGISTRATION_ID);
        } else {
            relyingPartyRegistrationBuilder = RelyingPartyRegistration.withRegistrationId(REGISTRATION_ID)
                    .entityId(registration.getEntityId())
                    .assertingPartyMetadata(metadata -> {
                        var singlesignon = registration.getAssertingparty().getSinglesignon();
                        var singlelogout = registration.getAssertingparty().getSinglelogout();

                        metadata.entityId(registration.getEntityId())
                                .verificationX509Credentials(
                                        verificationCredentials -> {
                                            try {
                                                X509Certificate certificate = CertificateUtil.readCertificate(
                                                        registration.getAssertingparty()
                                                                .getVerification()
                                                                .getCredentials()
                                                                .get(0)
                                                                .getCertificateLocation()
                                                );
                                                Saml2X509Credential verificationCredential = Saml2X509Credential.verification(certificate);
                                                verificationCredentials.add(verificationCredential);
                                            } catch (IOException ioe) {
                                                log.error("Error while retrieving verification credentials", ioe);
                                            }
                                        })
                                .singleSignOnServiceBinding(singlesignon.getBinding())
                                .singleSignOnServiceLocation(singlesignon.getUrl())
                                .singleLogoutServiceBinding(singlelogout.getBinding())
                                .singleLogoutServiceLocation(singlelogout.getUrl())
                                .singleLogoutServiceResponseLocation(singlelogout.getResponseUrl());
                    });
        }

        RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistrationBuilder
                .assertionConsumerServiceBinding(registration.getAcs().getBinding())
                .assertionConsumerServiceLocation(registration.getAcs().getLocation())
                .singleLogoutServiceBinding(registration.getSinglelogout().getBinding())
                .singleLogoutServiceLocation(registration.getSinglelogout().getUrl())
                .singleLogoutServiceResponseLocation(registration.getSinglelogout().getResponseUrl())
                .signingX509Credentials(signingCredentials -> {
                    var credential = registration
                            .getSigning()
                            .getCredentials()
                            .get(0);

                    try {
                        Saml2X509Credential saml2X509Credential = Saml2X509Credential.signing(
                                CertificateUtil.readPrivateKey(credential.getPrivateKeyLocation()),
                                CertificateUtil.readCertificate(credential.getCertificateLocation()
                                ));

                        signingCredentials.add(saml2X509Credential);
                    } catch (IOException ioe) {
                        log.error("Error while retrieving signing credentials", ioe);
                    }
                })
                .build();
        return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
    }

    @Bean
    @Override
    public OpenSaml5AuthenticationRequestResolver authenticationRequestResolver() {
        OpenSaml5AuthenticationRequestResolver resolver =
                new OpenSaml5AuthenticationRequestResolver(relyingPartyRegistrations());

        resolver.setAuthnRequestCustomizer(
                customizer -> {
                    HttpServletRequest request = customizer.getRequest();
                    AuthnRequest authnRequest = customizer.getAuthnRequest();
                    HttpSessionSaml2AuthenticationRequestRepository requestRepository =
                            new HttpSessionSaml2AuthenticationRequestRepository();
                    AbstractSaml2AuthenticationRequest saml2AuthenticationRequest =
                            requestRepository.loadAuthenticationRequest(request);

                    if (saml2AuthenticationRequest != null) {
                        String sessionId = request.getSession(false).getId();

                        log.debug(
                                "Retrieving SAML 2 authentication request ID from the current HTTP session {}",
                                sessionId);

                        String authenticationRequestId = saml2AuthenticationRequest.getId();

                        if (!authenticationRequestId.isBlank()) {
                            authnRequest.setID(authenticationRequestId);
                        } else {
                            log.warn(
                                    "No authentication request found for HTTP session {}. Generating new ID",
                                    sessionId);
                            authnRequest.setID("ARQ" + UUID.randomUUID().toString().substring(1));
                        }
                    } else {
                        log.debug("Generating new authentication request ID");
                        authnRequest.setID("ARQ" + UUID.randomUUID().toString().substring(1));
                    }

                    logAuthnRequestDetails(authnRequest);
                    logHttpRequestDetails(request);
                });
        return resolver;
    }

    private static void logAuthnRequestDetails(AuthnRequest authnRequest) {
        String message =
                """
                        AuthnRequest:
                        
                        ID: {}
                        Issuer: {}
                        IssueInstant: {}
                        AssertionConsumerService (ACS) URL: {}
                        """;
        log.debug(
                message,
                authnRequest.getID(),
                authnRequest.getIssuer() != null ? authnRequest.getIssuer().getValue() : null,
                authnRequest.getIssueInstant(),
                authnRequest.getAssertionConsumerServiceURL());

        if (authnRequest.getNameIDPolicy() != null) {
            log.debug("NameIDPolicy Format: {}", authnRequest.getNameIDPolicy().getFormat());
        }
    }

    private static void logHttpRequestDetails(HttpServletRequest request) {
        log.debug("HTTP Headers: ");
        Collections.list(request.getHeaderNames())
                .forEach(
                        headerName ->
                                log.debug("{}: {}", headerName, request.getHeader(headerName)));
        String message =
                """
                        HTTP Request Method: {}
                        Session ID: {}
                        Request Path: {}
                        Query String: {}
                        Remote Address: {}
                        
                        SAML Request Parameters:
                        
                        SAMLRequest: {}
                        RelayState: {}
                        """;
        log.debug(
                message,
                request.getMethod(),
                request.getSession().getId(),
                request.getRequestURI(),
                request.getQueryString(),
                request.getRemoteAddr(),
                request.getParameter("SAMLRequest"),
                request.getParameter("RelayState"));
    }

}
