package stirling.software.spdf.enterprise.config.sso;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider;
import org.springframework.security.saml2.provider.service.metadata.OpenSaml5MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.CachingRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.IterableRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.HttpSessionSaml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml5AuthenticationRequestResolver;
import stirling.software.spdf.enterprise.util.CertificateUtil;

@Slf4j
@Configuration
@ConditionalOnProperty(value = "stirling-pdf.enterprise-edition.enabled", havingValue = "true")
public class SAML2Configuration {

    @Autowired
    private Saml2RelyingPartyProperties saml2Properties;

    @Autowired
    private final ConcurrentMapCacheFactoryBean registrationsCache;

    @Autowired
    private final CacheManager cacheManager;

    public SAML2Configuration(ConcurrentMapCacheFactoryBean registrationsCache, CacheManager cacheManager) {
        this.registrationsCache = registrationsCache;
        this.cacheManager = cacheManager;
    }

    @Bean
    public OpenSaml5AuthenticationProvider authenticationProvider() {
        OpenSaml5AuthenticationProvider authenticationProvider = new OpenSaml5AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(new Saml2ResponseAuthenticationConverter());

        return authenticationProvider;
    }

    @Bean
    public OpenSaml5MetadataResolver metadataResolver() {
        return new OpenSaml5MetadataResolver();
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository(CacheManager cacheManager) {
        Set<Map.Entry<String, Saml2RelyingPartyProperties.Registration>> registrationEntries = saml2Properties.getRegistration().entrySet();

        Callable<IterableRelyingPartyRegistrationRepository> delegate = () -> {
            List<RelyingPartyRegistration> relyingPartyRegistrations = new ArrayList<>();

            registrationEntries.forEach(registrationEntry -> {
                Saml2RelyingPartyProperties.Registration registrationProperties = registrationEntry.getValue();

                RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistration
                        .withRegistrationId(registrationEntry.getKey())
                        .entityId(registrationProperties.getEntityId())
                        .assertionConsumerServiceBinding(registrationProperties.getAcs().getBinding())
                        .assertionConsumerServiceLocation(registrationProperties.getAcs().getLocation())
                        .singleLogoutServiceBinding(registrationProperties.getSinglelogout().getBinding())
                        .singleLogoutServiceLocation(registrationProperties.getSinglelogout().getUrl())
                        .singleLogoutServiceResponseLocation(registrationProperties.getSinglelogout().getResponseUrl())
                        .signingX509Credentials(signingCredentials -> {
                            var credential = registrationProperties
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
                        .assertingPartyMetadata(metadata -> {
                            var singlesignon = registrationProperties.getAssertingparty().getSinglesignon();
                            var singlelogout = registrationProperties.getAssertingparty().getSinglelogout();

                            metadata.entityId(registrationProperties.getEntityId())
                                    .verificationX509Credentials(
                                            verificationCredentials -> {
                                                try {
                                                    X509Certificate certificate = CertificateUtil.readCertificate(registrationProperties.getAssertingparty().getVerification().getCredentials().get(0).getCertificateLocation());
                                                    Saml2X509Credential verificationCredential = Saml2X509Credential.verification(certificate);
                                                    verificationCredentials.add(verificationCredential);
                                                } catch (IOException ioe) {
                                                    log.error("Error while retrieving signing credentials", ioe);
                                                }
                                            })
                                    .singleSignOnServiceBinding(singlesignon.getBinding())
                                    .singleSignOnServiceLocation(singlesignon.getUrl())
                                    .singleLogoutServiceBinding(singlelogout.getBinding())
                                    .singleLogoutServiceLocation(singlelogout.getUrl())
                                    .singleLogoutServiceResponseLocation(singlelogout.getResponseUrl());
//                                    .wantAuthnRequestsSigned(singlesignon.isSignRequest());
                        })
//                        .authnRequestsSigned(false)
                        .build();

                relyingPartyRegistrations.add(relyingPartyRegistration);
            });

            return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistrations);
        };

        CachingRelyingPartyRegistrationRepository registrations =
                new CachingRelyingPartyRegistrationRepository(delegate);
        registrations.setCache(cacheManager.getCache("relying-party-registrations-cache"));

        return registrations;
    }

    @Bean
    public OpenSaml5AuthenticationRequestResolver authenticationRequestResolver(
            RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        OpenSaml5AuthenticationRequestResolver resolver =
                new OpenSaml5AuthenticationRequestResolver(relyingPartyRegistrationRepository);

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
