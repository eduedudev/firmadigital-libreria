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
        cer.append("MIIHTDCCBTSgAwIBAgIUWrTV+f5ddmsv0L9jFBLxZQIwZD4wDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgZQxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwG\n");
        cer.append("A1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3Jl\n");
        cer.append("IFJvb3QgQ0ExMB4XDTI2MDEyMjIxNTgwM1oXDTM4MDExOTIxNTgwM1owgZQxCzAJ\n");
        cer.append("BgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcMBVFVSVRPMSMw\n");
        cer.append("IQYDVQQKDBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwGA1UECwwVRW50\n");
        cer.append("ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3JlIFJvb3QgQ0Ex\n");
        cer.append("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmJ2oh2FfrvTpbzqaSTdy\n");
        cer.append("zSB/hxJI2nWMLLDMjlPtSR7ilSwyaQ7ChvBPYXistpelHRulSf0PiuM85aQWQNTa\n");
        cer.append("PPpuNtkaIqWrf+ATjrhb9mjgCiUPBO9OG3fAaV+VtgOPH/aaygbqZkKHMMgzpGqv\n");
        cer.append("/rt/if9fpdDFysw5UmABEaVO6Juz7Wy/cGB167Im5N4WUE40giBw1c1i7nNjM3nf\n");
        cer.append("axMyYVAyMfeoJXamTFXS3SKMaSz3ttFLoC30t+XIjUCcaXkjT30qF7OO9YQ0RXW5\n");
        cer.append("wV9konuh410QL5g6/u1zsHKZ3Yrd3FrZPM0cVeVcvWdeM7hzSfOW0OMo/I7WQmX/\n");
        cer.append("fhja1e+Uq4RLG4AY6KDmvlV8KTAoSHC/Vj5KPe2CW+l+vFQ9ka6BgOJ0h2zINa7r\n");
        cer.append("jR8mWoPiGRGITl55oxpHFHTqWJ2K0kazBP/BxEIRIfPt9H0IuajE/SFN8WJeLKKG\n");
        cer.append("gUbVJm3q4tqCRXHsvDn4POmbQByhZ2sxoBIXS78jGx3RBfag6j++zA1sHs1ANj7W\n");
        cer.append("yWIWLp7tLiAVvkTRmCkh6prLoGAyw7+bzuwt/vvuEGQig8Wio3jcaBB+4F8tr2Ti\n");
        cer.append("9yPwcW7WRoRVQA4uwp0fh4h1k2s8l33Sv7J3K2ggxxGifdANZ39mvu6W/gXnjthO\n");
        cer.append("ga1heYVDI0BY6WRfqfo6uqkCAwEAAaOCAZIwggGOMB0GA1UdDgQWBBSQoZEvNSBZ\n");
        cer.append("yLAZZpfOMZG4GZTwnTAfBgNVHSMEGDAWgBSQoZEvNSBZyLAZZpfOMZG4GZTwnTAO\n");
        cer.append("BgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBAjAwBgNVHR8EKTAnMCWg\n");
        cer.append("I6Ahhh9odHRwOi8vcGNjYTEub25saW5lL2NybC9jYTEuY3JsMIHUBgNVHSAEgcww\n");
        cer.append("gckwgcYGCSsGAQQBg/A2ATCBuDBABggrBgEFBQcCARY0aHR0cHM6Ly9wcmltZWNv\n");
        cer.append("cmUuZGlnaXRhbC9wb2xpdGljYXMvY2VydGlmaWNhZG9zLnBkZjB0BggrBgEFBQcC\n");
        cer.append("AjBoGmZFbCBwcmVzZW50ZSBjZXJ0aWZpY2FkbyBlcyBlbWl0aWRvIGVuIGJhc2Ug\n");
        cer.append("YSBsYXMgcG9sw610aWNhcyBkZSBzZWd1cmlkYWQgZGUgUFJJTUVDT1JFTEFUIFMu\n");
        cer.append("QS5TLiBCLkkuQy4wHwYDVR0RBBgwFoEUZmlybWFzQHByaW1lY29yZS5sYXQwDQYJ\n");
        cer.append("KoZIhvcNAQELBQADggIBAD/IINoQIMbaNdAScMCeilKGjfwO36a3A0woflUh0RWV\n");
        cer.append("++V/kBxvPiq89WxKZbgwA/W8ZTXHYMU3nzjpo2+trfR6BcTgEjAsrABBi2RgS6NA\n");
        cer.append("bSY1c5b+EFCdjUd0N0Y9f+NBfuRVuwlCnB7iCg0REsEeOcbi9VpGDV7kozzSbGen\n");
        cer.append("ef3hdO1r96QFEE+LSRi0dR0eJX//9XnQKV9XyBZIgfZ9f5yQZ79nQ9cEDSW1wGIP\n");
        cer.append("e3aKnemZdVkjo5B7qVHCIKC2EjgTcwRdy8ecBjn44OkvlM95eBvm5590u+XKCHi5\n");
        cer.append("+zVavB9DDjWRsu8dglJgiHFRWbPiJNkQHJcbZUe7KvnFsAIMQVCsXckR6u4Y6rie\n");
        cer.append("X+am/25uZiHVz2LpsN0k7HVewU3Ai4izMGHn1VV9dPhBC8sAr+KX5JCfZTcoFqr8\n");
        cer.append("L1RTK7Og3vA+jCAsGidPbROZ3kCPJfNv5Ql49BqqqoBaKDsT7WhFqiXVkcR4uXzI\n");
        cer.append("JPGeF6XcxOA5wMZ5y57+KtE4ikt+wL9FYuH3Hf/Lh9nJp7/ZD0SUUp/X9AmQwoGc\n");
        cer.append("2JdYuHjqw8VmsXptwoC6dEvVmNqFSIdhQJ7xjB7zaDyXC+622x7x3FoTyXxG4tFW\n");
        cer.append("6Au0q9LgxaJKQFFU0ZFOb3RWmBhVMn5S+I0BID7s9VvagtWdbLupecDUB29DpmAJ\n");
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
