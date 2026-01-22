/*
 * Copyright (C) 2025
 * Authors: Misael Fernández, DARKCAM S.A.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.*
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package ec.gob.firmadigital.libreria.certificate.ec.darkcam;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.Set;

/**
 * Certificado subordinado de DARKCAM S.A. (SubCA), representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author DARKCAM S.A.
 */
public class DarkcamSubCaCert20252035 extends X509Certificate {

    private final X509Certificate certificate;

    public DarkcamSubCaCert20252035() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIGcjCCBFqgAwIBAgIRAJCwW5+wMvrhj7Ea5MfaHeYwDQYJKoZIhvcNAQELBQAw\n");
        cer.append("aDELMAkGA1UEBhMCRUMxFTATBgNVBAoMDERBUktDQU0gUy5BLjEMMAoGA1UECwwD\n");
        cer.append("UEtJMRIwEAYDVQQIDAlQaWNoaW5jaGExEDAOBgNVBAMMB0NBIFJvb3QxDjAMBgNV\n");
        cer.append("BAcMBVF1aXRvMB4XDTI1MTAwNjAzMDAwNFoXDTM1MTAwNjAzNTkyNFowgZUxCzAJ\n");
        cer.append("BgNVBAYTAkVDMRUwEwYDVQQKDAxEQVJLQ0FNIFMuQS4xIzAhBgNVBAsMGkNBIEVt\n");
        cer.append("aXNvcmEgZGUgQ2VydGlmaWNhZG9zMRIwEAYDVQQIDAlQaWNoaW5jaGExJjAkBgNV\n");
        cer.append("BAMMHURBUktDQU0gUy5BLiAtIENBIFN1Ym9yZGluYWRhMQ4wDAYDVQQHDAVRdWl0\n");
        cer.append("bzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIxS1k78jZ2S80FXGReG\n");
        cer.append("wGotvx+KfTjBl7iye0s6DWeDEUAAtyOMmDcyPNlr384QfdNiMH5qwHhXedd8A/WS\n");
        cer.append("duMAf38DU85ws1S2jAJRzN2VaRMPFiNOWkdf6XvR73NkjupwxGhtnU7vChSBIMs7\n");
        cer.append("XJZhYAtoUn0iox3nzmb8DJ2ZfxJnIXf1cSNChH9hK/tpKVqF0pamZnSv8DOum8p+\n");
        cer.append("1wgkeRBwTxvVccmc38uyx9WSJ6rpv5xmdYm86qPAJW9tqDnqLEyX2tMkbZwclSuz\n");
        cer.append("630rMF66y/DjUobQULV1DTyr7vjClZeI1QWLSM7Z/8lE3RIDPewUcZJuVCZuyxGr\n");
        cer.append("07rQyoI4baumHfmsQ19b3X5bFEKwNLW1sX0t5M16DD4IfzmJ5FSrjv+1jsiFBHBB\n");
        cer.append("D41q83/QOJZGmQeYN9+TiN1xj+GdJZOKdHCg0HyPe3oOHjsoXY1bLHzeiIH5ynLa\n");
        cer.append("Ggo379BSmd/ZzZQUwse5kX2xev8jFvq3+e1sb/wq0uXZ/QArlvdAKYfGLmyY9CsP\n");
        cer.append("KT+0fX/zkWxHmQkciIfuts6jAmNIzJDgCdxHOeIXnCmldGcgmbXbykCocfnlT8uT\n");
        cer.append("fzILdGd1G9rNYN5MFzgTcVZVzd68rNbYYJcwzug0qpeyDB+gwS1ftVlPpBDsW9AW\n");
        cer.append("PjdyfY4bvrHJtBaV3G18nk6LAgMBAAGjgegwgeUwEgYDVR0TAQH/BAgwBgEB/wIB\n");
        cer.append("ADAfBgNVHSMEGDAWgBRHdTrh2MxDeaoqCmjdjGr/8ZtvBDAdBgNVHQ4EFgQUecoX\n");
        cer.append("bb0lCvRwRkheSg0R9g5L0sIwDgYDVR0PAQH/BAQDAgGGMH8GA1UdHwR4MHYwdKBy\n");
        cer.append("oHCGbmh0dHA6Ly9jYS1yb290LWNybC1kYXJrY2FtLnMzLnVzLWVhc3QtMS5hbWF6\n");
        cer.append("b25hd3MuY29tL2NybC80NjI0ZGIxZC1iMTY3LTQyZWItOGRmYi0yYTg2MGFlMGVi\n");
        cer.append("NDQvMlRXdFlUZkx5R2wuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQAVicze4GVvA8NK\n");
        cer.append("VpJMNui0yglkvOUjqq0UTtFj4AaJPdg7Sdvv4sAnYqjFUNcyskmGX8sU5yFYoXIQ\n");
        cer.append("dHdPDzotuYEzfyjHb2D7K3is26wT6FwDMaJtfHYv1G+E8ruooin+6iJFCeaTKMi9\n");
        cer.append("s3ZYB1luDi4fiXeVp2iTseoDY9+k0wV8uXXkSa5dvEee3NHMxqpZfQHW4odrk73s\n");
        cer.append("CeZP8lwpi15OGwE69L2r+hlAcuJslTq3snTcpz7hQvW8Y/49b0myuKJbGoboLxO3\n");
        cer.append("mzd0WNR2qVXLrDDpkSekkVkYOh5bNTsHexoNsatXuU/ts2I1v8d11Dv3gMknNrn7\n");
        cer.append("1AqQlEVtJCP/j6Rnz7FTLBC2QFHOR+yDxievJOm0b79iJQOGZiYWjfTTfkrU/MUd\n");
        cer.append("5y7oqNLGEn9Pk+O+GVDBCT1i2I6RtgSdsO3H7sBRpBSYXWpddlFw/+cbi6gwIFzq\n");
        cer.append("DHpqCoo3SeBDsubivDylOF5ohUsmV524F8RfD95hwTstDi1KkbvB1JzHDl8rFZ+w\n");
        cer.append("Bmgcte5EijFV1oGgjrkh8Id52QeWz1GC7gPuhw9mdfRZdjQYvKhwjXLMEaaKlQqn\n");
        cer.append("wloKg0xCZ67a7nSyqpEucyImoM9V2oN+SW62PxlFF2VPmxfdY8pg4OO39pouSBi9\n");
        cer.append("uPoRD9T13AFwY2b53AJLi9+kga1XmQ==\n");
        cer.append("-----END CERTIFICATE-----\n");

        try {
            InputStream is = new ByteArrayInputStream(cer.toString().getBytes("UTF-8"));
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            this.certificate = (X509Certificate) cf.generateCertificate(is);
        } catch (UnsupportedEncodingException | GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        certificate.checkValidity();
    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        certificate.checkValidity(date);
    }

    @Override
    public int getBasicConstraints() {
        return certificate.getBasicConstraints();
    }

    @Override
    public Principal getIssuerDN() {
        return certificate.getIssuerDN();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        return certificate.getIssuerUniqueID();
    }

    @Override
    public boolean[] getKeyUsage() {
        return certificate.getKeyUsage();
    }

    @Override
    public Date getNotAfter() {
        return certificate.getNotAfter();
    }

    @Override
    public Date getNotBefore() {
        return certificate.getNotBefore();
    }

    @Override
    public BigInteger getSerialNumber() {
        return certificate.getSerialNumber();
    }

    @Override
    public String getSigAlgName() {
        return certificate.getSigAlgName();
    }

    @Override
    public String getSigAlgOID() {
        return certificate.getSigAlgOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        return certificate.getSigAlgParams();
    }

    @Override
    public byte[] getSignature() {
        return certificate.getSignature();
    }

    @Override
    public Principal getSubjectDN() {
        return certificate.getSubjectDN();
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        return certificate.getSubjectUniqueID();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return certificate.getTBSCertificate();
    }

    @Override
    public int getVersion() {
        return certificate.getVersion();
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return certificate.getEncoded();
    }

    @Override
    public PublicKey getPublicKey() {
        return certificate.getPublicKey();
    }

    @Override
    public String toString() {
        return certificate.toString();
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException {
        certificate.verify(key);
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        certificate.verify(key, sigProvider);
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return certificate.getCriticalExtensionOIDs();
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        return certificate.getExtensionValue(oid);
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return certificate.getNonCriticalExtensionOIDs();
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return certificate.hasUnsupportedCriticalExtension();
    }
}
