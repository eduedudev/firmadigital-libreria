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
        cer.append("MIIFezCCA2OgAwIBAgIUfQF3wrilqBFVLT7EHkxUmkXUCzEwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgZQxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwG\n");
        cer.append("A1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3Jl\n");
        cer.append("IFJvb3QgQ0ExMB4XDTI2MDEyMjIxNTgwM1oXDTM4MDExOTIxNTgwM1owYjELMAkG\n");
        cer.append("A1UEBhMCRUMxIzAhBgNVBAoMGlBSSU1FQ09SRUxBVCBTLkEuUy4gQi5JLkMuMR4w\n");
        cer.append("HAYDVQQDDBVQcmltZSBDb3JlIEVtaXNvciBDQTExDjAMBgNVBAcMBVFVSVRPMIIB\n");
        cer.append("IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs1D94rNsTlXOYRmjGJ3nWDbE\n");
        cer.append("s+By9cK7n8IB36PRIXsgDYHtNdHer6upepbAONPOnEAU+vAEwcwhAOkHhCYYDd3m\n");
        cer.append("A2iu3Z97p/CJ6lhIaboPSp/2kgJMsE5A3qCsiYaAmr6roy2dtmS+/GiUdWrvZlz4\n");
        cer.append("SHXi+2NBA2WIQ8AEDJmuA8O68vbE6DvV8vJO+DM0wDxkuZ3REOhgpi/mopoKuuB/\n");
        cer.append("w857N6mT8HEen1sQz6+vmIzlKwZp1LKMuhEpA+iSaApmyfHnpIQv+wmpRrQYQYxQ\n");
        cer.append("d/EvcTtsYtw8YN15FQ3Ii0tbqkGBobijLY9q9OdIttzJxD+hDjZaN75Q++kPWQID\n");
        cer.append("AQABo4H1MIHyMB0GA1UdDgQWBBQOABAjZHoeAtgSRoX2dEZB3jR9KTAfBgNVHSME\n");
        cer.append("GDAWgBSQoZEvNSBZyLAZZpfOMZG4GZTwnTASBgNVHRMBAf8ECDAGAQH/AgEAMA4G\n");
        cer.append("A1UdDwEB/wQEAwIBhjAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGNjYTEub25s\n");
        cer.append("aW5lL2NybC9jYTEuY3JsMDkGCCsGAQUFBwEBBC0wKzApBggrBgEFBQcwAYYdaHR0\n");
        cer.append("cDovL3BjY2ExLm9ubGluZTozMDQ0L29jc3AwHwYDVR0RBBgwFoEUZmlybWFzQHBy\n");
        cer.append("aW1lY29yZS5sYXQwDQYJKoZIhvcNAQELBQADggIBAJYS7KwpzerxMp0oOMioSPA3\n");
        cer.append("7msj2vNSkf42NsN9eKFgoLo6gKb/BN8wKhyNBHajrvTy6XygGbn+mHavb1bMee9G\n");
        cer.append("x3XK7UaQp7OsNu3tEujt8TuLiJumKp3mX0XXC2avZBlysws55BpO1Ti2JbrmmSrD\n");
        cer.append("Jj2KGzkgkAAxfkpBzo8CVQK7q5UqCCac9jQ5SxJGOpbiYeLJsfiG7ijrkxeal7gW\n");
        cer.append("X7ImwdO3Tv4GoUtv5/8cQQCm22fLKOV7SmqucUGidU/rKFenBNa74r8rslP1KFiM\n");
        cer.append("7iy71O9hp6YG70ob8Ydcui3UPDgw92GZiJ/4pWVuGSzhtFHxBdwaRmlZwQyJK42f\n");
        cer.append("IkEMmIESGFvalbmCqinkVMJ8RiodA9nmPwexvMR+peo8kTOQH4RuJVn27MNB3d4d\n");
        cer.append("Y2d+9/ozuEwMC+D7XdKS8aHS8ngqnQHxRH6BZyRVwt4HhWuQf9MIAzG+lzUYWVK6\n");
        cer.append("skHvfiIEYGNoEEdUZ/c0H9I3LkkZ1vheILgWeqn649YHafv6hlSGhqpbExjOAq8r\n");
        cer.append("E0IKFBNbS/zKgPECXt+phTO7PmG2PNs8HKChPW5OLjT4/bfj4siV4Jm5kSxESqse\n");
        cer.append("5x6t+reOMVrTnq3RdeBcSlMBnK+oRIxJ/B9ZFbYCzOaOnlMADEGqHNHckZJANRXv\n");
        cer.append("SvHls/F8ZV2F9abIxumn\n");
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
