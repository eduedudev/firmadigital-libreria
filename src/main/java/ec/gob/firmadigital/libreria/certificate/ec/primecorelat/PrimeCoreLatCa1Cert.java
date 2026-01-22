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
public class PrimeCoreLatCa1Cert extends X509Certificate {

    private X509Certificate certificate;

    public PrimeCoreLatCa1Cert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIFEjCCA/qgAwIBAgIUahj9p46GHR9Aak+Ku/Pof3DXV+AwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgYsxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMRowGAYDVQQKDBFQcmltZSBDb3JlIFMuQS5TLjEeMBwGA1UECwwVRW50\n");
        cer.append("ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3JlIFJvb3QgQ0Ex\n");
        cer.append("MCAXDTI1MDkxMTA1NDgxN1oYDzIwNTUwOTA0MDU0ODE3WjCBizELMAkGA1UEBhMC\n");
        cer.append("RUMxEjAQBgNVBAgMCVBJQ0hJTkNIQTEOMAwGA1UEBwwFUVVJVE8xGjAYBgNVBAoM\n");
        cer.append("EVByaW1lIENvcmUgUy5BLlMuMR4wHAYDVQQLDBVFbnRlIGRlIENlcnRpZmljYWNp\n");
        cer.append("b24xHDAaBgNVBAMME1ByaW1lIENvcmUgUm9vdCBDQTEwggEiMA0GCSqGSIb3DQEB\n");
        cer.append("AQUAA4IBDwAwggEKAoIBAQCptXutSsf/6EEU4zf9ArKXClug9YrfSq273z1Tbu71\n");
        cer.append("u7Gaom/RCfOec64wVcCk1ThCpM5BDL28A+7C5L0h4cLeq9KGXaWPDRb8K0BMs9QV\n");
        cer.append("60rqpwk+MhvKT1awdFt9HDl9rtkBhWLo5oQoWkxkrV1sthUhHBBNuR6ws7l6xSrZ\n");
        cer.append("ALcpaPs4XDAnyXvTLPwsEhWHPbxtldFY7w8BzRFoQLFLIrK8rBKHSxjOrLkZnteP\n");
        cer.append("/goa6hI0TyODCK60PY3jHxOItuWI1FQDTf6J0TfXRuZyRQpCbn2fKRDmCFf4eX9V\n");
        cer.append("YaYb8sxpdQgvHUJU7Y8mNHH2RmHxkDquQ8j6WhsUmjQVAgMBAAGjggFoMIIBZDAd\n");
        cer.append("BgNVHQ4EFgQU86Tnfd/y2o30MXoBL8OyDU6IPu8wHwYDVR0jBBgwFoAU86Tnfd/y\n");
        cer.append("2o30MXoBL8OyDU6IPu8wDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8C\n");
        cer.append("AQIwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BjY2ExLm9ubGluZS9jcmwvY2Ex\n");
        cer.append("LmNybDCBywYDVR0gBIHDMIHAMIG9BgkrBgEEAYPwNgEwga8wQAYIKwYBBQUHAgEW\n");
        cer.append("NGh0dHBzOi8vcHJpbWVjb3JlLmRpZ2l0YWwvcG9saXRpY2FzL2NlcnRpZmljYWRv\n");
        cer.append("cy5wZGYwawYIKwYBBQUHAgIwXxpdRWwgcHJlc2VudGUgY2VydGlmaWNhZG8gZXMg\n");
        cer.append("ZW1pdGlkbyBlbiBiYXNlIGEgbGFzIHBvbMOtdGljYXMgZGUgc2VndXJpZGFkIGRl\n");
        cer.append("IFByaW1lIENvcmUgUy5BLlMuMA0GCSqGSIb3DQEBCwUAA4IBAQCcSzrklUhyJmMm\n");
        cer.append("FMGtUFd8QYPBUHq0kXXWo6rVwbLXRc+5BQYpuWqmIRCF76zMRkP3g5vHQa7VXMIh\n");
        cer.append("HpGeeZwbMy9PYmI0vwy7mys9Qor2eGPMvdkzwdri5Yshd4+swo9aVXNZGPL4O+kN\n");
        cer.append("hFm1F/jMYvUFynODUmAh/LvjOc0zsxXDstdD+ZrgWUugx/vw1EfcPUZmNs9BY+ja\n");
        cer.append("IfEWYMAjY1Rn4wZ93mu3FKeFNgLTWbej8MFjJeS16WMAfRUkj6GUx30IeCozUmm4\n");
        cer.append("CCFE08anGmcjv+2HTv5nNeVOXk7SIWyID7a2hZOIMNBVCNvvbi/EPaD1dIKI17y8\n");
        cer.append("mbqEncDk\n");
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
