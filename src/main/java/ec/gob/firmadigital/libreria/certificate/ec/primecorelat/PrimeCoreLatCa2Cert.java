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
        cer.append("MIIHTDCCBTSgAwIBAgIUHZrTsjvK11bpgVEmBefe2F/d/HUwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgZQxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwG\n");
        cer.append("A1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3Jl\n");
        cer.append("IFJvb3QgQ0EyMB4XDTI2MDEyMjIxMzY1M1oXDTM4MDExOTIxMzY1M1owgZQxCzAJ\n");
        cer.append("BgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcMBVFVSVRPMSMw\n");
        cer.append("IQYDVQQKDBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwGA1UECwwVRW50\n");
        cer.append("ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3JlIFJvb3QgQ0Ey\n");
        cer.append("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2DtgMUX/GviaLAaFiFI3\n");
        cer.append("oAVJrXQGZIvn3BxBozQrBzfFL30Ss7HGpmZg/U85t0HGJ17ynTfu4v1HQyjplrns\n");
        cer.append("5YRz/3Q+8ebWsRVRhP/CNzC/BexncEsVnMJrRkXBVv/DfBS18U3JERjDU7GQcDgr\n");
        cer.append("+SfA2bEftJ+CFJXjOUPQG44SBXYcnQNpNDqOCjThg82+w3Y9aoyAFfW9ob/GprH/\n");
        cer.append("WDJYTNTY8eHlUk0Ts60PAod0uNJ2k7lQ656vgSXcgXJtwaJGRZv88MPZz8KEqSoS\n");
        cer.append("dvcCidU+kTTcgVnHQwOdYPXkxr4a/J7K5bQwZhUgIHpIkBYygUMdMq42RHICdS35\n");
        cer.append("j8SxyJuKqLSyjYwdnTRQY2Onbrna3lJ8YbChJdwgwzN/1FUkdXOifhU897CsHbJA\n");
        cer.append("ka2JPVhiEAt67oam/8yjqL5BBcuV3aAli435ZFD5Sgt4gbVjVlGB8Jl8Wh+cy0he\n");
        cer.append("Kui+cz5kJg8xChQ24qcRNy2YW9SPXGuUHFJ8aehT4vaO6J3UB5IwdOp8Hcf3UoqZ\n");
        cer.append("w5dkOwc8v0uYq9GC7dZiUK+Bsxxxm/m4JjpY0RDX5GPBhNT0D4S29LyYBpaa0UJ+\n");
        cer.append("JGDzF3+k84RMuPseXtODwt0CNPWsxeyASnwAtwzeYmyNub5JCmnMrP9FIqpHu04e\n");
        cer.append("f64I3RdV6F6MP1KaPryB5QkCAwEAAaOCAZIwggGOMB0GA1UdDgQWBBT/9jk45u8/\n");
        cer.append("q9CdG0dLR6q4tbwvRDAfBgNVHSMEGDAWgBT/9jk45u8/q9CdG0dLR6q4tbwvRDAO\n");
        cer.append("BgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBAjAwBgNVHR8EKTAnMCWg\n");
        cer.append("I6Ahhh9odHRwOi8vcGNjYTIub25saW5lL2NybC9jYTIuY3JsMIHUBgNVHSAEgcww\n");
        cer.append("gckwgcYGCSsGAQQBg/A2ATCBuDBABggrBgEFBQcCARY0aHR0cHM6Ly9wcmltZWNv\n");
        cer.append("cmUuZGlnaXRhbC9wb2xpdGljYXMvY2VydGlmaWNhZG9zLnBkZjB0BggrBgEFBQcC\n");
        cer.append("AjBoGmZFbCBwcmVzZW50ZSBjZXJ0aWZpY2FkbyBlcyBlbWl0aWRvIGVuIGJhc2Ug\n");
        cer.append("YSBsYXMgcG9sw610aWNhcyBkZSBzZWd1cmlkYWQgZGUgUFJJTUVDT1JFTEFUIFMu\n");
        cer.append("QS5TLiBCLkkuQy4wHwYDVR0RBBgwFoEUZmlybWFzQHByaW1lY29yZS5sYXQwDQYJ\n");
        cer.append("KoZIhvcNAQELBQADggIBAHD1hFsUgz2PSEjIiSI7M87GDGTAC0nufOR6eZ+/sHYv\n");
        cer.append("qtlXnRgd2+YRS+z9J1bO9Gw81MQt0tuo6o1kx1Q75KHoPUNSiT8t+IKg0+Yaa2zB\n");
        cer.append("ibXx9uL+LrIh2RKCSUJP8HrA/kdVY4Rq8//UyUp1VaXu+aua1uhgelAesevizaZu\n");
        cer.append("3h40YMVjeXOpSMc0vhRHgB1EqmzwmG84xxoo0ny2ZA43//jzoUVIjo3LzU3ApL0y\n");
        cer.append("t11+fF9YPL8OixK6WwnCuwk+4FDRTWPStmyFGpvUBIJaWOBXPKtNaa0RMklYS86b\n");
        cer.append("7hJlG/6i2Y29jZ0//aYoTRcK9QEJYTzazNwx/5sfvL0HuVtZln7qKwgJWpdo4hVQ\n");
        cer.append("slKr2FtZAWzgmfS8qMEZ7Rtyn+mAiL8V2U3k/xqX02ykYlBfybOV4YdajeyL7F4D\n");
        cer.append("dOMLotB1GDQ/TnmLN7wlvgosK7oD4gQg5kGygk+cbSiGZOv8dKJbtx2/Nw2gbqm5\n");
        cer.append("8pOe1z1YdCDJMUsXCWrfPHR0POROpsbXgBSCyjq6+gUMZ+o+vYCTYaEA1d8rcZQ6\n");
        cer.append("N1u4NznHJsLGqvwCx9jrrv3VQ7Sqy7IjsvppglLVuztn2ZoGH1EjI0V7kX2N4n/o\n");
        cer.append("40tPPhFZcs2H38Lns6JabE/EwumfV+/1J5QjkQr0LPpPBoKieyrt3Cz3+1yLQaMp\n");
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
