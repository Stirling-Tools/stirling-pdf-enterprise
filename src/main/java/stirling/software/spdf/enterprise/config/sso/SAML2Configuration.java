package stirling.software.spdf.enterprise.config.sso;

import com.google.common.cache.Cache;
import jakarta.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.core.Saml2X509Credential.Saml2X509CredentialType;
import org.springframework.security.saml2.provider.service.registration.*;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import stirling.software.SPDF.model.ApplicationProperties;
import stirling.software.SPDF.model.ApplicationProperties.Security.SAML2;

@Configuration
@Slf4j
@ConditionalOnProperty(
        value = "security.saml2.enabled",
        havingValue = "true")
public class SAML2Configuration {

    private final Saml2RelyingPartyProperties saml2Properties;

    public SAML2Configuration(Saml2RelyingPartyProperties saml2Properties) {
        this.saml2Properties = saml2Properties;
    }

    @Bean
    public RelyingPartyRegistrationRepository registrations(CacheManager cacheManager) {
        List<RelyingPartyRegistrations> relyingPartyRegistrations = new ArrayList<>();

        saml2Properties.getRegistration().forEach((idpName, idpRegistration) -> {
            Saml2RelyingPartyProperties.Registration.Signing.Credential creds = idpRegistration.getSigning().getCredentials().get(0);
            Saml2X509Credential credential = new Saml2X509Credential(
                    (RSAPrivateKey) creds.getPrivateKeyLocation(),
                    (X509Certificate) creds.getCertificateLocation(),
                    Saml2X509CredentialType.SIGNING);

            relyingPartyRegistrations.add(
                    RelyingPartyRegistration.withRegistrationId(idpName)
                            .entityId(idpName)
                            .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
                            .signingX509Credentials(saml2X509Credentials -> saml2X509Credentials.add(credential))
                            .authnRequestsSigned(false)
                            .
                            .assertingPartyMetadata()
            )
        });
        Supplier<IterableRelyingPartyRegistrationRepository> delegate = () ->
                new InMemoryRelyingPartyRegistrationRepository(RelyingPartyRegistrations
                        .fromMetadataLocation("https://idp.example.org/ap/metadata")
                        .registrationId("ap").build());

        CachingRelyingPartyRegistrationRepository registrations =
                new CachingRelyingPartyRegistrationRepository(delegate);
        registrations.setCache(cacheManager.getCache("relying-party-registrations"));
        return registrations;
    }

    @Bean
    @ConditionalOnProperty(
            name = "security.saml2.enabled",
            havingValue = "true")
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {
        SAML2 samlConf = applicationProperties.getSecurity().getSaml2();
        X509Certificate idpCert = CertificateUtils.readCertificate();
        Saml2X509Credential verificationCredential = Saml2X509Credential.verification(idpCert);
        Resource privateKeyResource = samlConf.getPrivateKey();
        Resource certificateResource = samlConf.getSpCert();
        Saml2X509Credential signingCredential =
                new Saml2X509Credential(
                        CertificateUtils.readPrivateKey(privateKeyResource),
                        CertificateUtils.readCertificate(certificateResource),
                        Saml2X509CredentialType.SIGNING);
        RelyingPartyRegistration rp =
                RelyingPartyRegistration.withRegistrationId(samlConf.getRegistrationId())
                        .signingX509Credentials(c -> c.add(signingCredential))
                        .assertingPartyMetadata(
                                metadata ->
                                        metadata.entityId(samlConf.getIdpIssuer())
                                                .singleSignOnServiceLocation(
                                                        samlConf.getIdpSingleLoginUrl())
                                                .verificationX509Credentials(
                                                        c -> c.add(verificationCredential))
                                                .singleSignOnServiceBinding(
                                                        Saml2MessageBinding.POST)
                                                .wantAuthnRequestsSigned(true))
                        .build();
        return new InMemoryRelyingPartyRegistrationRepository(rp);
    }

    @Bean
    @ConditionalOnProperty(
            name = "security.saml2.enabled",
            havingValue = "true",
            matchIfMissing = false)
    public OpenSaml4AuthenticationRequestResolver authenticationRequestResolver(
            RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        OpenSaml4AuthenticationRequestResolver resolver =
                new OpenSaml4AuthenticationRequestResolver(relyingPartyRegistrationRepository);
        resolver.setAuthnRequestCustomizer(
                customizer -> {
                    log.debug("Customizing SAML Authentication request");
                    AuthnRequest authnRequest = customizer.getAuthnRequest();
                    log.debug("AuthnRequest ID: {}", authnRequest.getID());
                    if (authnRequest.getID() == null) {
                        authnRequest.setID("ARQ" + UUID.randomUUID().toString());
                    }
                    log.debug("AuthnRequest new ID after set: {}", authnRequest.getID());
                    log.debug("AuthnRequest IssueInstant: {}", authnRequest.getIssueInstant());
                    log.debug(
                            "AuthnRequest Issuer: {}",
                            authnRequest.getIssuer() != null
                                    ? authnRequest.getIssuer().getValue()
                                    : "null");
                    HttpServletRequest request = customizer.getRequest();
                    // Log HTTP request details
                    log.debug("HTTP Request Method: {}", request.getMethod());
                    log.debug("Request URI: {}", request.getRequestURI());
                    log.debug("Request URL: {}", request.getRequestURL().toString());
                    log.debug("Query String: {}", request.getQueryString());
                    log.debug("Remote Address: {}", request.getRemoteAddr());
                    // Log headers
                    Collections.list(request.getHeaderNames())
                            .forEach(
                                    headerName -> {
                                        log.debug(
                                                "Header - {}: {}",
                                                headerName,
                                                request.getHeader(headerName));
                                    });
                    // Log SAML specific parameters
                    log.debug("SAML Request Parameters:");
                    log.debug("SAMLRequest: {}", request.getParameter("SAMLRequest"));
                    log.debug("RelayState: {}", request.getParameter("RelayState"));
                    // Log session debugrmation if exists
                    if (request.getSession(false) != null) {
                        log.debug("Session ID: {}", request.getSession().getId());
                    }
                    // Log any assertions consumer service details if present
                    if (authnRequest.getAssertionConsumerServiceURL() != null) {
                        log.debug(
                                "AssertionConsumerServiceURL: {}",
                                authnRequest.getAssertionConsumerServiceURL());
                    }
                    // Log NameID policy if present
                    if (authnRequest.getNameIDPolicy() != null) {
                        log.debug(
                                "NameIDPolicy Format: {}",
                                authnRequest.getNameIDPolicy().getFormat());
                    }
                });
        return resolver;
    }
}
