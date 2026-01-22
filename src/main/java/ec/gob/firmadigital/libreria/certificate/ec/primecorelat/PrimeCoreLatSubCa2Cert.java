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
public class PrimeCoreLatSubCa2Cert extends X509Certificate {

    private X509Certificate certificate;

    public PrimeCoreLatSubCa2Cert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIEOjCCAyKgAwIBAgIUcN0I1qodkRSIG+Bov0OEyJCHTgAwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgYsxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMRowGAYDVQQKDBFQcmltZSBDb3JlIFMuQS5TLjEeMBwGA1UECwwVRW50\n");
        cer.append("ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3JlIFJvb3QgQ0Ey\n");
        cer.append("MCAXDTI1MDkxMTA1NDUyNFoYDzIwNTUwOTA0MDU0NTI0WjBJMQswCQYDVQQGEwJF\n");
        cer.append("QzEaMBgGA1UECgwRUHJpbWUgQ29yZSBTLkEuUy4xHjAcBgNVBAMMFVByaW1lIENv\n");
        cer.append("cmUgRW1pc29yIENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMl8\n");
        cer.append("7h853HhF7JVwbGZG6eDFSHnxmAvBkER4ZcRFInZ4jdFNJtVHr76i6gORzNWsB3q6\n");
        cer.append("ERKkd/QCUWwYFTu4M8tBtRb436rB+TXmEodZxU8y63GTDv8s32/nSfz8DHMiMXMx\n");
        cer.append("YiKcq7oQY/G3ouSPufTG+rzpKROQx7HokV3DxN9t8T6+m6BfCa8QSfutX5KOuIcM\n");
        cer.append("YPHeAhfDwhyHtJUPwb8DqhDtxIf1MSqFlnIlhoRMD2Ihsr5335M6a4T7wkYt1L9w\n");
        cer.append("/9JmKC7Rci/P2QZk8977uEqnk34H0ZJpoTpnjKk2RlU+Tw0kKUZmqX4N1FCVKfW8\n");
        cer.append("8y9VrV5iGyflqNA72wkCAwEAAaOB1DCB0TAdBgNVHQ4EFgQUho7m3IlxCi2uCNZn\n");
        cer.append("yUH7mvZnq+wwHwYDVR0jBBgwFoAUbKsSI3T95Ceuyx+pTL/rlZOOLzAwEgYDVR0T\n");
        cer.append("AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwMAYDVR0fBCkwJzAloCOgIYYf\n");
        cer.append("aHR0cDovL3BjY2EyLm9ubGluZS9jcmwvY2EyLmNybDA5BggrBgEFBQcBAQQtMCsw\n");
        cer.append("KQYIKwYBBQUHMAGGHWh0dHA6Ly9wY2NhMi5vbmxpbmU6MzA0NC9vY3NwMA0GCSqG\n");
        cer.append("SIb3DQEBCwUAA4IBAQAIx0iLhReG69TuPccKAczOKFNtSQtFPXZdt7U9XoWtdeW+\n");
        cer.append("KzGFqeYm2m6Zogcjsj+f9NvCP32eNZqAy9AEzU70gL6jAJVME+pPKXjFz65oazIg\n");
        cer.append("VddZflaq0mXmMP9Gu6hdzAD5kGCaY6xQIMnApthIWl60i2BPBHntrFwTcqPG2du+\n");
        cer.append("DmaTuXjhkzom61cWeQ/uB+bqLdxCCUxJ03bkP5CDzWmNKkrQImu2ODdYDIeebGe5\n");
        cer.append("W+cEQQbmufO0XS4ArGknqaVn2D5z+mxy2RrUqm+jWTcfdYaPbap/vMV53iMc8Qrz\n");
        cer.append("7g6Xl/lHlBdQW/edI5It99V9D9skq7EfUOnilz43\n");
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
