package stirling.software.spdf.enterprise.config.security;

import com.google.common.cache.Cache;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.*;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Duration;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private static final String REGISTRATION_ID = "stirlingpdf";

    @Value("${spring.security.saml2.relyingparty.registration.stirlingpdf.assertingparty.metadata-uri}")
    private String metadataUri;

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
                .fromMetadataLocation(metadataUri)
                .registrationId(REGISTRATION_ID)
                .build();

        InMemoryRelyingPartyRegistrationRepository delegate =
                new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);

        Cache<String, RelyingPartyRegistration> cache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofHours(1)) // Refresh metadata every hour
                .maximumSize(10)
                .build();

        return new CachingRelyingPartyRegistrationRepository(delegate, cache::get, cache::put);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        Saml2MetadataFilter filter = new Saml2MetadataFilter(relyingPartyRegistrationResolver(), new OpenSamlMetadataResolver());

        http.csrf(AbstractHttpConfigurer::disable).authorizeHttpRequests(authorize -> authorize.anyRequest()
                        .authenticated())
                .saml2Login(
                saml2 -> {
                    saml2.loginPage("/saml2")
                            .relyingPartyRegistrationRepository(
                                    saml2RelyingPartyRegistrations)
                            .authenticationManager(
                                    new ProviderManager(authenticationProvider))
                            .successHandler(
                                    new CustomSaml2AuthenticationSuccessHandler(
                                            loginAttemptService,
                                            applicationProperties,
                                            userService))
                            .failureHandler(
                                    new CustomSaml2AuthenticationFailureHandler())
                            .authenticationRequestResolver(
                                    saml2AuthenticationRequestResolver);
                }
        ).saml2Logout(Customizer.withDefaults())
                .addFilter()
        return http.build();
    }
}
