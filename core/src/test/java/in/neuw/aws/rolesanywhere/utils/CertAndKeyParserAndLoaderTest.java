package in.neuw.aws.rolesanywhere.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.neuw.aws.rolesanywhere.credentials.IAMRolesAnywhereSessionsCredentialsProvider;
import in.neuw.aws.rolesanywhere.props.AwsRolesAnywhereProperties;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.iam.model.IamException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class CertAndKeyParserAndLoaderTest {
    private static final String PEM_CERT_HEADER = "-----BEGIN CERTIFICATE-----\n";
    private static final String PEM_CERT_FOOTER = "\n-----END CERTIFICATE-----\n";
    private static final String SIGNED_CERT = """
            MIIDZDCCAkygAwIBAgIULfK7DhweOAwsk6HcqaujuYb+VxowDQYJKoZIhvcNAQEL
            BQAwTDEQMA4GA1UEAwwHVGVzdCBDQTELMAkGA1UEBhMCSU4xDTALBgNVBAgMBFRl
            c3QxDTALBgNVBAcMBFRlc3QxDTALBgNVBAoMBHRlc3QwHhcNMjUxMDMxMTAzNzE3
            WhcNMjcxMDMxMTAzNzE3WjBPMRMwEQYDVQQDDAp0ZXN0Q2xpZW50MQswCQYDVQQG
            EwJJTjENMAsGA1UECAwEVGVzdDENMAsGA1UEBwwEVGVzdDENMAsGA1UECgwEdGVz
            dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALng6etuLZT5BSyQ8jUu
            PyZDyAz6YlPt/saQ4BaUBJUkL4hAlIY9EBwQBw2yhuefOWtfj9U/mQC6Yc9dHcrf
            45ZV0CAvbl6tpJRkknLVOvpsLS3fC27fOZwUOUwFn4azpzF9wNgI360HQD8Qrjhg
            mZ5NV7exPWMcWU7hbU3mbyP1u7Hh4BKS5gkL0XgRpkviAOVD8L66NqvYsJdyd+ly
            20v18zhwgkhNEDx5a3pv199sivM6zK8SjaoBvcogIHPQvyQuJ7tOJ2i4FjiOWQrr
            3MjZB+goMVXjGkl/Y7JOYKyFv2uAsJhnCcY6H4028yMFMp8t3fMf7uk4AmshjgKj
            fMcCAwEAAaM7MDkwHwYDVR0jBBgwFoAUJnZz5YPfafkxKxCKv2TUoYTMgSkwCQYD
            VR0TBAIwADALBgNVHQ8EBAMCBPAwDQYJKoZIhvcNAQELBQADggEBANj4IDj29S7M
            ZQSvL2F7K+bgD9et6LmSo6JIbXzipZcKoFR36uToMl8ytgU/8J0EwLeEN39krYa+
            jiHqS1a8bxn+cXjaSfb9te3LpVKaEWnwabJqM4gzLPo/CuwYIQwOHwMlRUPY3JjM
            LFq8CF3YevWPts3xcqp34JRTREPIQNztdrEQpJBAKPXkFh8XneiURRFrPeofK327
            CetRTiXBhLIaGTpeGUSmHH7UTeKaRB8C4mMtIe23imrdub8vhyvaKYtStgZri/74
            MEY1rUdqHfYWwcKddTx0+XV80UNqdfrBzWxOfwMgJlbrm7X/jIhwhBvkb5XODYK3
            HyrUoNy737E=""";
    private static final String CA_CERT = """
            MIIDeTCCAmGgAwIBAgIUcxAY8UkCCYNxFtx+G4Cu9BQFnugwDQYJKoZIhvcNAQEL
            BQAwTDEQMA4GA1UEAwwHVGVzdCBDQTELMAkGA1UEBhMCSU4xDTALBgNVBAgMBFRl
            c3QxDTALBgNVBAcMBFRlc3QxDTALBgNVBAoMBHRlc3QwHhcNMjUxMDMxMTAyOTA3
            WhcNMzAxMDMxMTAyOTA3WjBMMRAwDgYDVQQDDAdUZXN0IENBMQswCQYDVQQGEwJJ
            TjENMAsGA1UECAwEVGVzdDENMAsGA1UEBwwEVGVzdDENMAsGA1UECgwEdGVzdDCC
            ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOnStYPbxtmW9aW4XmlINbjZ
            VasW4SygfWeVyme4BIUBQJP6OhxLQ2yILxVe5d9dujZcVEa1GkWpNltCr1Z/dsL9
            +p8nf9fNGA/+Z9xX3iS7LcY1JTMM3lGEPA4vGYP4N9+bRovxroyaXW8x9GE1bPC0
            /f3VnIYu8Oyj0HJXIsT+Kh1jN/SgKtiCGAET8Zw69wfMigzqsrSWs3xCJ8Yj5sTU
            n44iLcPeot2yrB+CghUwm/Gxt6c/RyoDgTJlBWSgS971LUruKcUdqz+uQRD8xkvK
            vQuV/sh1UYdkySsuHa4Fjtx7cd/iYkM5GDuwsN8axGh3XtjqESw4+FOoQCAMPJkC
            AwEAAaNTMFEwHQYDVR0OBBYEFCZ2c+WD32n5MSsQir9k1KGEzIEpMB8GA1UdIwQY
            MBaAFCZ2c+WD32n5MSsQir9k1KGEzIEpMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
            hvcNAQELBQADggEBANodNMd6HIFZjgLfllIeGZ/h9hae/aCt+jVTYn7VKvRZH0Fq
            PtQB9yjyCzX1h4ekomctdAoGub0T9bZq3L1YiOE0OrrqUpbKZhZKdV7jHJW15oej
            DwrQyo7wQyrtpl3aa1pirsNaPJ2M67asmuBZuQtn9bKLLSns4PzyoIM4DI6T3OCu
            Bw3nRqDPfBHH60Qbi0IQq0pRuU6O+lW/J1Xq1KBdnj8Y05zgbGF5aVEOmBjSkSuH
            jNaDrhcbigdKNMLntbd4tmdz2ZU96ZK9+HO3Gn2pdtoo8FXhAKZPpsJE7fUP8FTZ
            Xv4rvhuMK/coXiRWuPMiTH4W4HIZ90a2dKXbxpQ=""";


    @Test
    void couldBeBase64() {
        assertTrue(CertAndKeyParserAndLoader.isEncodedBase64(CA_CERT.replace("\n", "").replace("\r", "")));
        assertTrue(CertAndKeyParserAndLoader.isEncodedBase64(SIGNED_CERT.replace("\n", "").replace("\r", "")));
    }

    private void performTest_encodedCertificateConfiguration(String configuredCertValue) {
        final AwsRolesAnywhereProperties properties = new AwsRolesAnywhereProperties();
        properties.setRoleArn("abc");
        properties.setProfileArn("abc");
        properties.setTrustAnchorArn("abc");
        properties.setRegion("us-east-1");
        properties.setEncodedX509Certificate(configuredCertValue);
        properties.setDurationSeconds(30);
        properties.setEncodedPrivateKey(Base64.getEncoder().encodeToString(
                ("-----BEGIN PRIVATE KEY-----\n" +
                        """
                                MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC54Onrbi2U+QUs
                                kPI1Lj8mQ8gM+mJT7f7GkOAWlASVJC+IQJSGPRAcEAcNsobnnzlrX4/VP5kAumHP
                                XR3K3+OWVdAgL25eraSUZJJy1Tr6bC0t3wtu3zmcFDlMBZ+Gs6cxfcDYCN+tB0A/
                                EK44YJmeTVe3sT1jHFlO4W1N5m8j9bux4eASkuYJC9F4EaZL4gDlQ/C+ujar2LCX
                                cnfpcttL9fM4cIJITRA8eWt6b9ffbIrzOsyvEo2qAb3KICBz0L8kLie7TidouBY4
                                jlkK69zI2QfoKDFV4xpJf2OyTmCshb9rgLCYZwnGOh+NNvMjBTKfLd3zH+7pOAJr
                                IY4Co3zHAgMBAAECggEARDebIeBJskbB810uxv22B2EQ5lJuC8donY9F7oNcOzAQ
                                kbzBxZJbezEWpZxDjnYNKK7lpqm0iWPdybCu4mnQqLfNrkI6C11G7X8LkEFZZ9aT
                                riYRmBsslW+Gp7PYnCMK1UsFn0OCc4oZtgt1JROuzT4tVykhEmKxFBX/e3t6hoNk
                                TC5h6Xs53yX9dRk+eYObXybwiGb4gukr9yn4PoyNOpUyMKTyTnOieSmDU/hu7qC1
                                l1nBBmJjE4yyxrwevGaCpe7xFgxEGZEjKUDsf8/v5lnbYEznuAyqsvHMtfIMigof
                                E+PYBpNJH1JwSWdzmr0Gz4p/74+bLq41Vl5t1k7gwQKBgQDrkUa2X1O64Ic+3FS7
                                R5M8UTwFjuW+p9ExQLKoYkc6vadikA1kJwT12tMk2Q3riUleevdgCClAE+6Ff/LL
                                k56wfYcBkOtNW+bRpdUJjHKdBSq8RODW78w2fDB68Tm2LViWDdQ7s3/SX+hkOW+R
                                ZzyDQVPjromRVpzWJ3QeJU2cSQKBgQDKAE5hAXyGdIPB4Cs7n5jWg+nHhDe+HaQk
                                A14xnSxEpZyjadrDUz5NFD/WLPGqhsLeN6RykYCuoqMN2V3ZyZ4p77x9QyZqcWhb
                                UzOxfhX39aT+8DUsc2k9+o8+KUYGoHveq0F3zliYZidU7/y3f2gcGHvZ47Fe/vF4
                                mBrkxB+wjwKBgQDfwZfEZVoYGWv99rV5Sux9D8COmwR5i9g2C3loXinAjyMuiRxf
                                NH0OtvN2fcIuJ7KMTwsoqbfdCNG49yb93lOO2z1g7HHFgnUGUJnCPykjIyRLvrU/
                                FHoKiv5V2UpzVDFgHvSoXMEeaEFK6g+issgU+PmhPEmpxvakqMcwV0iYGQKBgQDD
                                wOQz0ZLxYXxFp4197D3atF8bACBc1rC4TaM8hUnfBHb1TaG4Y7UeUR9D2K4hSRMS
                                8e0lMaf4lJda1mjCo0Xo8fBBm49g26H7zndr6/oyHxTUEcgV2YoFjAjAfpLj3SXt
                                NRzuk0L7/RLkluTallc30upCzwqWOo2bBhwZ0Y28NQKBgQCzwPPdYRRtTpiR96i+
                                JkQz+89VZjDPuqw8c5/eGRxrgOxrqjucwEFJJRQHLAHRKgGRVbgLHZ8j1qYG53iE
                                rkaDQNdKis0SpvzaYkkFEcFJcuUBQyD9LTYpF1z/9CBGsUp3yc8BfFh1sO458OSS
                                yyZH6Iw71i2/SE82k9+hW4ndJA==
                                """.replace("\n", "").replace("\r", "") +
                        "\n-----END PRIVATE KEY-----"
                ).getBytes(StandardCharsets.US_ASCII)));
        try (final var prov = new IAMRolesAnywhereSessionsCredentialsProvider
                .Builder(properties, new ObjectMapper())
                .prefetch(true)
                .asyncCredentialUpdateEnabled(true)
                .build()) {
            assertNotNull(prov);
        } catch (IamException e) {
            // success case, configuration could be parsed and request to AWS service was issued
            assertEquals("Error while trying to connect to AWS ROLES ANYWHERE", e.getMessage());
        }
    }

    @Test
    void openSslGeneratedCertificateConfigurationWithoutPemHeader() {
        performTest_encodedCertificateConfiguration(CA_CERT);
    }

    @Test
    void openSslGeneratedCertificateConfigurationWithPemHeader() {
        performTest_encodedCertificateConfiguration(PEM_CERT_HEADER + CA_CERT + PEM_CERT_FOOTER);
    }

    @Test
    void base64encodedCertWithoutPemHeader() {
        performTest_encodedCertificateConfiguration(
                Base64.getEncoder().encodeToString(CA_CERT.getBytes(StandardCharsets.US_ASCII))
        );
    }

    @Test
    void base64encodedCertWithPemHeader() {
        performTest_encodedCertificateConfiguration(
                Base64.getEncoder().encodeToString((PEM_CERT_HEADER + CA_CERT + PEM_CERT_FOOTER)
                        .getBytes(StandardCharsets.US_ASCII))
        );
    }

    @Test
    void certChain() {
        // must include PEM header, otherwise the concatenated certificates can not be distinguished
        performTest_encodedCertificateConfiguration(
                PEM_CERT_HEADER + SIGNED_CERT + PEM_CERT_FOOTER +
                        PEM_CERT_HEADER + CA_CERT + PEM_CERT_FOOTER
        );
    }

    @Test
    void base64encodedCertChain() {
        performTest_encodedCertificateConfiguration(
                Base64.getEncoder().encodeToString((
                        PEM_CERT_HEADER + SIGNED_CERT + PEM_CERT_FOOTER +
                                PEM_CERT_HEADER + CA_CERT + PEM_CERT_FOOTER
                ).getBytes(StandardCharsets.US_ASCII))
        );
    }
}
