package in.neuw.aws.rolesanywhere.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.neuw.aws.rolesanywhere.credentials.IAMRolesAnywhereSessionsCredentialsProvider;
import in.neuw.aws.rolesanywhere.props.AwsRolesAnywhereProperties;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertNotNull;

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

    private void performTest_encodedCertificateConfiguration(String configuredCertValue) {
        final AwsRolesAnywhereProperties properties = new AwsRolesAnywhereProperties();
        properties.setRoleArn("");
        properties.setProfileArn("");
        properties.setTrustAnchorArn("");
        properties.setRegion("us-east-1");
        properties.setEncodedX509Certificate(configuredCertValue);
        try (final var prov = new IAMRolesAnywhereSessionsCredentialsProvider
                .Builder(properties, new ObjectMapper())
                .prefetch(true)
                .asyncCredentialUpdateEnabled(true)
                .build()) {
            assertNotNull(prov);
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