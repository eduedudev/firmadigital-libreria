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
 * Certificado intermedio de Lazzate, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class LazzateSubCaWeGoCert extends X509Certificate {

    private X509Certificate certificate;

    public LazzateSubCaWeGoCert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIElTCCA32gAwIBAgIUdssCoHezFX53bXPQvzEsxiuEQrowDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgbIxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMT0wOwYDVQQKDDRXRS1HTyBURVJDRVIgVklOQ1VMQURPIExBWlpBVEUg\n");
        cer.append("RU5URSBERSBDRVJUSUZJQ0FDSU9OMRYwFAYDVQQLDA1XRS1HTyBMQVpaQVRFMSgw\n");
        cer.append("JgYDVQQDDB9XRS1HTyBURVJDRVIgVklOQ1VMQURPIFJvb3QgQ0ExMCAXDTIzMTEz\n");
        cer.append("MDA4MTI0MloYDzIwNTMxMTIyMDgxMjQyWjB4MQswCQYDVQQGEwJFQzE9MDsGA1UE\n");
        cer.append("Cgw0V0UtR08gVEVSQ0VSIFZJTkNVTEFETyBMQVpaQVRFIEVOVEUgREUgQ0VSVElG\n");
        cer.append("SUNBQ0lPTjEqMCgGA1UEAwwhV0UtR08gVEVSQ0VSIFZJTkNVTEFETyBFbWlzb3Ig\n");
        cer.append("Q0ExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtoo8ykcQZ2LA3lcc\n");
        cer.append("sUS3++ABFulLomfrlDSQDbcRvMX1TlGT4K7cJwejimOkLD9KvZJYjqUejqUlGSsj\n");
        cer.append("jUpIP2pif2sGVejIQiK2r5OxkfxEuHzEWLqpfafv9c89rRT8e9TUBJvT8VIj2wab\n");
        cer.append("UaviDIoFPW2hD4ppaRNmLydj2zkxQTnKVKooqmoFD/PC34dJRSvPCR1T8POhGs9s\n");
        cer.append("83XL5yoPBVFwQvb+KXvgYIYDWyAPpARDltYKdHZfM2VMOy5hE3ZJ40YI5cnqnZSL\n");
        cer.append("VSDJvuFDlQ45fiDRNDACWPr43Y8Xb6DSr8+Y2FLfHTPj1VLbCzNIa1jDijxAtYbR\n");
        cer.append("5WymTQIDAQABo4HZMIHWMB0GA1UdDgQWBBRU9qYwTxsNCvEwRwYUW9BcosVPpTAf\n");
        cer.append("BgNVHSMEGDAWgBQcpO1M4S/fWE+SLlEAeB+JvdzEGzASBgNVHRMBAf8ECDAGAQH/\n");
        cer.append("AgEAMA4GA1UdDwEB/wQEAwIBhjAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vd2Ut\n");
        cer.append("Z28ueHl6L2NybC9lbWlzb3JDQTEuY3JsMDsGCCsGAQUFBwEBBC8wLTArBggrBgEF\n");
        cer.append("BQcwAYYfaHR0cDovL3dlLWdvLnh5ejo4Nzc3L2Fkc3Mvb2NzcDANBgkqhkiG9w0B\n");
        cer.append("AQsFAAOCAQEAApBoFXsIW9vHA8axBZTpKbFgDuGppMc8CwT+3RNbQshfrK4Rkgqb\n");
        cer.append("4CPscHB6Rsm5bGWN49w7Vxe3OIki1mBAlnTLSkLSVijNeoP0jj5ndu9ohcY9k7Ej\n");
        cer.append("RbiNjRsxb8RTFvaJdzn2sDAdre9rEYc6UyxwG87inUTOSg0viWkPaf8lWfrhg3Sq\n");
        cer.append("wR36Hmr2SM/KRDx812kkj4/x2VyOhFNzvJ3m+ohm6+Z9BEOX/uDIZZUYhaUqAq6t\n");
        cer.append("jxM0A5ffryHkR84GiyKPeu4460dip4aSyaxqC8AYlZt1F0q2R3KKe/vZMgSa5QqM\n");
        cer.append("sE12wx842tnx722ajF/zhU7m3yZQaLENtg==\n");
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
