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
 * Certificado subordinado de PRIMECORELAT (SubCA), representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class PrimeCoreLatSubCa1Cert extends X509Certificate {

    private X509Certificate certificate;

    public PrimeCoreLatSubCa1Cert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIEOjCCAyKgAwIBAgIUTe1SJZn3RCbJWD1/LeHRSzBb1r0wDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgYsxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMRowGAYDVQQKDBFQcmltZSBDb3JlIFMuQS5TLjEeMBwGA1UECwwVRW50\n");
        cer.append("ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3JlIFJvb3QgQ0Ex\n");
        cer.append("MCAXDTI1MDkxMTA1NDgxOFoYDzIwNTUwOTA0MDU0ODE4WjBJMQswCQYDVQQGEwJF\n");
        cer.append("QzEaMBgGA1UECgwRUHJpbWUgQ29yZSBTLkEuUy4xHjAcBgNVBAMMFVByaW1lIENv\n");
        cer.append("cmUgRW1pc29yIENBMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJsq\n");
        cer.append("6sdyUloGV7YEOlWksGWzk+z78S/nEf6ctCKLyAmTYEIJ56msOTGbNoD0n+6j72/z\n");
        cer.append("r+r8qDwcevS4pbHFzgi1Cbix5ROm6cKMwcWRvPaR29YwIr4l0u2UP8cq5amKM4ik\n");
        cer.append("rXyNAqBw3rTTuOqEhoHhpX/qpAkrMy4OnpX6asOHu66l+AlpkBkKb+kNcbv8xezR\n");
        cer.append("dt3Kkmx5srbYHzOGAeKe/17FiOHr+FMblNOp7SvFaisekBHQU22nERW96pRa+Dk9\n");
        cer.append("n8fENPkLQRS0RpvH5+EfZYLNJkD3EZ1/Z7OCu2kn+GIcStUYTMpFvSz80fux+hEj\n");
        cer.append("UZNsIXtROPD9pDPTBuUCAwEAAaOB1DCB0TAdBgNVHQ4EFgQUoYm2DLinj5WyWsJf\n");
        cer.append("6D0Jg129rBEwHwYDVR0jBBgwFoAU86Tnfd/y2o30MXoBL8OyDU6IPu8wEgYDVR0T\n");
        cer.append("AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwMAYDVR0fBCkwJzAloCOgIYYf\n");
        cer.append("aHR0cDovL3BjY2ExLm9ubGluZS9jcmwvY2ExLmNybDA5BggrBgEFBQcBAQQtMCsw\n");
        cer.append("KQYIKwYBBQUHMAGGHWh0dHA6Ly9wY2NhMS5vbmxpbmU6MzA0NC9vY3NwMA0GCSqG\n");
        cer.append("SIb3DQEBCwUAA4IBAQBZuXz5y3/+EuKl35R8CHGpcTPznl7ubjDMhIwL08XrmQz5\n");
        cer.append("gIAIgFmtLoJokAXmHk6C+WyWjR6TuOP1S5R9js0YYeCNUWvD4P4iE0gAAc2OBeVJ\n");
        cer.append("bh6mBShy+DvK1AUAqKqZiW5nLy9ANOEBAYAj3XCuLedHKAs90S6DFZZpAKmYG4vP\n");
        cer.append("YQHrYPo4c/ZjQRjOquTcw2KRp7Nh8Eag+kRFyEYA+uZjiis5E4v8Eb+99SbFuq8A\n");
        cer.append("AerqbQFW4222rzZDVpahTN2tGOef5evgzuWQNvqfDw3oZK81FdcCSinWxu4vkser\n");
        cer.append("ofAY+lMrjpolHvWrj7OR33yTMkXQn+hhaDs1jFO7\n");
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
