package stirling.software.spdf.enterprise.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider;
import org.springframework.security.saml2.provider.service.metadata.OpenSaml5MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml5AuthenticationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import stirling.software.spdf.enterprise.config.sso.Saml2AuthenticationFailureHandler;
import stirling.software.spdf.enterprise.config.sso.Saml2AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Autowired
    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Autowired
    private final OpenSaml5AuthenticationRequestResolver saml2AuthenticationRequestResolver;

    @Autowired
    private final OpenSaml5MetadataResolver metadataResolver;

    @Autowired
    private final OpenSaml5AuthenticationProvider authenticationProvider;

    public SecurityConfiguration(
            RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
            OpenSaml5AuthenticationRequestResolver saml2AuthenticationRequestResolver,
            OpenSaml5MetadataResolver metadataResolver,
            OpenSaml5AuthenticationProvider authenticationProvider
    ) {
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
        this.saml2AuthenticationRequestResolver = saml2AuthenticationRequestResolver;
        this.metadataResolver = metadataResolver;
        this.authenticationProvider = authenticationProvider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .saml2Login(saml2 ->
                        saml2
                                .loginPage("/saml2/authenticate/stirling-pdf")
                                .relyingPartyRegistrationRepository(relyingPartyRegistrationRepository)
                                .authenticationManager(new ProviderManager(authenticationProvider))
                                .successHandler(new Saml2AuthenticationSuccessHandler())
                                .failureHandler(new Saml2AuthenticationFailureHandler())
                                .authenticationRequestResolver(saml2AuthenticationRequestResolver)
                )
                .saml2Logout(logout ->
                        logout
                                .logoutUrl("{baseUrl}/login?logout=true")
                                .relyingPartyRegistrationRepository(relyingPartyRegistrationRepository)
                                .logoutRequest(Customizer.withDefaults())
                                .logoutResponse(Customizer.withDefaults())
                );
        return http.build();
    }
}
