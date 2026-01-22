/*
 * Copyright (C) 2025
 * Authors: Misael Fernández, PrimeCoreLat
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
package ec.gob.firmadigital.libreria.certificate.ec.primecorelat;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

/**
 * Certificado raiz de PRIMECORELAT, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class PrimeCoreLatCa2Cert extends X509Certificate {

    private X509Certificate certificate;

    public PrimeCoreLatCa2Cert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIFEjCCA/qgAwIBAgIUGtTI7dClvZ8vVvarvfXqhp2lhFswDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgYsxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMRowGAYDVQQKDBFQcmltZSBDb3JlIFMuQS5TLjEeMBwGA1UECwwVRW50\n");
        cer.append("ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3JlIFJvb3QgQ0Ey\n");
        cer.append("MCAXDTI1MDkxMTA1NDUyM1oYDzIwNTUwOTA0MDU0NTIzWjCBizELMAkGA1UEBhMC\n");
        cer.append("RUMxEjAQBgNVBAgMCVBJQ0hJTkNIQTEOMAwGA1UEBwwFUVVJVE8xGjAYBgNVBAoM\n");
        cer.append("EVByaW1lIENvcmUgUy5BLlMuMR4wHAYDVQQLDBVFbnRlIGRlIENlcnRpZmljYWNp\n");
        cer.append("b24xHDAaBgNVBAMME1ByaW1lIENvcmUgUm9vdCBDQTIwggEiMA0GCSqGSIb3DQEB\n");
        cer.append("AQUAA4IBDwAwggEKAoIBAQDDgwJFtbZNXaDh6VndcgEq44d296r9RtjGZ3D29GOf\n");
        cer.append("0aaMrEdfkWAQnk60RdBqmSqA8DWPsquDz1Up/YazvO+rCN1j6VfVASOZER7NPzoR\n");
        cer.append("Fvmzf/8tZOETFEK9SP1/PuF0uzC8S2dgp7XgoOv2HUpnTSqlzn2amK060KdDzIk4\n");
        cer.append("4vJWDYR42c4VrN5H9yDAw0yVmbSjXsWsLIpxU+8F64gFWlzOjEIsa5rjgCZzygEB\n");
        cer.append("Pkwihuvwnjskz5p0oYz1RyEuDtK06aXS8fs3d03pxerYtn9UzT0xb8enzPrCD4iF\n");
        cer.append("Jne2Ezj7UYOPG2I7htISOYFfIjAbB1bN9z/UJhKQb5ZvAgMBAAGjggFoMIIBZDAd\n");
        cer.append("BgNVHQ4EFgQUbKsSI3T95Ceuyx+pTL/rlZOOLzAwHwYDVR0jBBgwFoAUbKsSI3T9\n");
        cer.append("5Ceuyx+pTL/rlZOOLzAwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8C\n");
        cer.append("AQIwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BjY2EyLm9ubGluZS9jcmwvY2Ey\n");
        cer.append("LmNybDCBywYDVR0gBIHDMIHAMIG9BgkrBgEEAYPwNgEwga8wQAYIKwYBBQUHAgEW\n");
        cer.append("NGh0dHBzOi8vcHJpbWVjb3JlLmRpZ2l0YWwvcG9saXRpY2FzL2NlcnRpZmljYWRv\n");
        cer.append("cy5wZGYwawYIKwYBBQUHAgIwXxpdRWwgcHJlc2VudGUgY2VydGlmaWNhZG8gZXMg\n");
        cer.append("ZW1pdGlkbyBlbiBiYXNlIGEgbGFzIHBvbMOtdGljYXMgZGUgc2VndXJpZGFkIGRl\n");
        cer.append("IFByaW1lIENvcmUgUy5BLlMuMA0GCSqGSIb3DQEBCwUAA4IBAQCb5KBSDbWo82hr\n");
        cer.append("hlLL6a+kzhMtXWH/CDj7YYRjmFCiHjpazzbTEsndovHEmjwGRbuIWIr17x6kABnW\n");
        cer.append("RNYO+mVqVLD6tZ7bicwg4TImP5Jwf2F4veRc+y+kAyv1uS2hhU5PrM4SUwELPb0n\n");
        cer.append("E6gRvdMt7cHokYAhhmiBiEJ0uE/j5WN7YPJxUQJUHKXtSVtuatxchLpEC/7g2fOr\n");
        cer.append("3LP8Ivgx76O3pWBcDnmqcpdV2DzbToTzrJ573iiPIBINtwCuTOgjZsKaNXs3NkOm\n");
        cer.append("e8tah68Iu4k0X233go78VvjeK7i4/PCdrNxO3tzfND9oRc2xCJc9+8ZK2qI0C77n\n");
        cer.append("yuEdtNty\n");
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
