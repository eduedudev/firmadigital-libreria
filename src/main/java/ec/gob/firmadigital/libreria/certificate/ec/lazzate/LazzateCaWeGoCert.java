/*
 * Copyright (C) 2024
 * Authors: Henry Carrera
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
package ec.gob.firmadigital.libreria.certificate.ec.lazzate;

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
 * Certificado raiz de Lazzate, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class LazzateCaWeGoCert extends X509Certificate {

    private X509Certificate certificate;

    public LazzateCaWeGoCert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIFjDCCBHSgAwIBAgIUWbVWfWaJLz77qu0wpdC7L22Q5wkwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgbIxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMT0wOwYDVQQKDDRXRS1HTyBURVJDRVIgVklOQ1VMQURPIExBWlpBVEUg\n");
        cer.append("RU5URSBERSBDRVJUSUZJQ0FDSU9OMRYwFAYDVQQLDA1XRS1HTyBMQVpaQVRFMSgw\n");
        cer.append("JgYDVQQDDB9XRS1HTyBURVJDRVIgVklOQ1VMQURPIFJvb3QgQ0ExMCAXDTIzMTEz\n");
        cer.append("MDA4MTI0MloYDzIwNTMxMTIyMDgxMjQyWjCBsjELMAkGA1UEBhMCRUMxEjAQBgNV\n");
        cer.append("BAgMCVBJQ0hJTkNIQTEOMAwGA1UEBwwFUVVJVE8xPTA7BgNVBAoMNFdFLUdPIFRF\n");
        cer.append("UkNFUiBWSU5DVUxBRE8gTEFaWkFURSBFTlRFIERFIENFUlRJRklDQUNJT04xFjAU\n");
        cer.append("BgNVBAsMDVdFLUdPIExBWlpBVEUxKDAmBgNVBAMMH1dFLUdPIFRFUkNFUiBWSU5D\n");
        cer.append("VUxBRE8gUm9vdCBDQTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCu\n");
        cer.append("DB7Q/Ql5gezSNF0TU95L4N+ZFfK/zU8eQpyr1VwcFXefFmDd5PzvcsOKxC8cpDqm\n");
        cer.append("XdqHDQvxpDUMjD0gdl3BLWyZ1p2nZ3cBlVTQFWpibMjTTEq6JT0NS6ItjGtgPo4M\n");
        cer.append("yt0yUfWSNvxSJyc6q0BE3uxFaFkjF+IUADhDYugkIPaHM9OgI2f/+dtASUCqsGnG\n");
        cer.append("tbcf8PICy3EwM2WPSjtzryA4qDdsxiL+8pVzWbYoMDJFicPSW4T4ZbgT7zLGYaPp\n");
        cer.append("+Iv1OWYsV8FQv+zDFjWLacF5XfBbmsu0I1NX014zC+JPcNrk8AJb49IVISuHJnAj\n");
        cer.append("SFolmih+Ya5IzOFtHYTtAgMBAAGjggGUMIIBkDAdBgNVHQ4EFgQUHKTtTOEv31hP\n");
        cer.append("ki5RAHgfib3cxBswHwYDVR0jBBgwFoAUHKTtTOEv31hPki5RAHgfib3cxBswDgYD\n");
        cer.append("VR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQIwNAYDVR0fBC0wKzApoCeg\n");
        cer.append("JYYjaHR0cDovL3dlLWdvLnh5ei9jcmwvbGF6emF0ZUNBMS5jcmwwgfMGA1UdIASB\n");
        cer.append("6zCB6DCB5QYJKwYBBAGDz3YBMIHXMEIGCCsGAQUFBwIBFjZodHRwczovL3dlLWdv\n");
        cer.append("Lnh5ei9kZXNjYXJnYXMvcG9saXRpY2FzL2NlcnRpZmljYWRvcy5wZGYwgZAGCCsG\n");
        cer.append("AQUFBwICMIGDGoGARWwgcHJlc2VudGUgY2VydGlmaWNhZG8gZXMgZW1pdGlkbyBl\n");
        cer.append("biBiYXNlIGEgbGFzIHBvbMOtdGljYXMgZGUgc2VndXJpZGFkIGRlIFdFLUdPIFRF\n");
        cer.append("UkNFUiBWSU5DVUxBRE8gTEFaWkFURSBFTlRFIERFIENFUlRJRklDQUNJT04wDQYJ\n");
        cer.append("KoZIhvcNAQELBQADggEBAKXgu9c/zHwfYAlTiwzR+ZFj4H3Sn6/KuLH2n1maG1q6\n");
        cer.append("s5MeiAc+i3v8XK3J2H1d6B9gjGzub/Ly+Ll1hzc2Acj/XEYDl+BVnV2KJqEPCA7I\n");
        cer.append("i8i/U14D/B6ZnmzJZCYk4ZF8bmadcttjlj/JB6gkFMSq9BOX9w9s1Pin2VAV5CdS\n");
        cer.append("n22nShW2qoKL0kRvFjE/GZH3sdVu9GUZMAxQ2CdKBM5YUdWjwwrGCHAWnWNykQ/v\n");
        cer.append("u9tkS9vGfi7SO4+ZH6S5pWIFDi5QGVJkgYtPHA/pu471cDblNjr+CT2nO04e4Vca\n");
        cer.append("zwLOHThHZK25dypAZ06GniML4gqx8sxhaQZyKW7f2so=\n");
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
