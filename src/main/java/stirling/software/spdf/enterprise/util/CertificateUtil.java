package stirling.software.spdf.enterprise.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.Resource;
// todo will conditional work on this? is it needed?
@ConditionalOnProperty(name = "stirling-pdf.enterprise-edition.enabled", havingValue = "true")
public class CertificateUtil {

    public static X509Certificate readCertificate(Resource certificateResource) throws IOException {
        try (PemReader pemReader =
                new PemReader(
                        new InputStreamReader(
                                certificateResource.getInputStream(), StandardCharsets.UTF_8))) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] decodedCert = pemObject.getContent();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedCert));
        } catch (IOException | CertificateException e) {
            throw new IOException("Error reading certificate: " + certificateResource.getFilename(), e);
        }
    }

    public static RSAPrivateKey readPrivateKey(Resource privateKeyResource) throws IOException {
        try (PEMParser pemParser =
                new PEMParser(
                        new InputStreamReader(
                                privateKeyResource.getInputStream(), StandardCharsets.UTF_8))) {

            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            if (object instanceof PEMKeyPair keypair) {
                // Handle traditional RSA private key format
                return (RSAPrivateKey) converter.getPrivateKey(keypair.getPrivateKeyInfo());
            } else if (object instanceof PrivateKeyInfo keyInfo) {
                // Handle PKCS#8 format
                return (RSAPrivateKey) converter.getPrivateKey(keyInfo);
            } else {
                throw new IllegalArgumentException(
                        "Unsupported key format: "
                                + (object != null ? object.getClass().getName() : "null"));
            }
        }
    }
}
