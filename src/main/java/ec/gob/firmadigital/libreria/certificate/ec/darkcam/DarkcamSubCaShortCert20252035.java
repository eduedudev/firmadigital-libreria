/*
 * Copyright (C) 2025
 * Authors: DARKCAM S.A.
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
 * Certificado subordinado de DARKCAM S.A. para certificados Short-Lived (SubCA Short),
 * representado como un objeto <code>X509Certificate</code>.
 *
 * Este SubCA se utiliza para emitir certificados de corta duración (short-lived certificates)
 * que típicamente tienen validez de horas o días, diseñados para escenarios "one-shot" donde
 * no se requiere revocación tradicional.
 *
 * @author DARKCAM S.A.
 */
public class DarkcamSubCaShortCert20252035 extends X509Certificate {

    private final X509Certificate certificate;

    public DarkcamSubCaShortCert20252035() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIGfzCCBGegAwIBAgIRAIQzP2cR/YG4NQIPUouLbSowDQYJKoZIhvcNAQELBQAw\n");
        cer.append("aDELMAkGA1UEBhMCRUMxFTATBgNVBAoMDERBUktDQU0gUy5BLjEMMAoGA1UECwwD\n");
        cer.append("UEtJMRIwEAYDVQQIDAlQaWNoaW5jaGExEDAOBgNVBAMMB0NBIFJvb3QxDjAMBgNV\n");
        cer.append("BAcMBVF1aXRvMB4XDTI1MTAzMTE5NTAyOFoXDTM1MTAzMTIwNDcwMFowgaIxCzAJ\n");
        cer.append("BgNVBAYTAkVDMRUwEwYDVQQKDAxEQVJLQ0FNIFMuQS4xKjAoBgNVBAsMIUNBIEVt\n");
        cer.append("aXNvcmEgZGUgQ2VydGlmaWNhY2lvbiBTaG9ydDESMBAGA1UECAwJUGljaGluY2hh\n");
        cer.append("MSwwKgYDVQQDDCNEQVJLQ0FNIFMuQS4gLSBDQSBTdWJvcmRpbmFkYSBTaG9ydDEO\n");
        cer.append("MAwGA1UEBwwFUXVpdG8wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDP\n");
        cer.append("tZnJVrjVbQQ7qseeJznHyflP+HzLSe7nIisbRalsnUkTvt7NiLN7h21p7FfFPcJB\n");
        cer.append("FEhDom5fykQnaw/j/SPUg7IM37iUY0UBsbQjWn4UhcrvS7weaPy8jm9zMgf81h0M\n");
        cer.append("Xzd2wb/XnsIfPrM7OOuAiIwBnunT18yaRF9ZPqXbaDq3lFlHzrxHMYJ56gjYTw/1\n");
        cer.append("3EGasbTPxvCXvpp9h/ScK1PjjLYZH7q6H2RipniyXhsr26AkcBGYWRFWel8YvYGz\n");
        cer.append("C0KXdVJ+PHpm7hBNzq5aKtabsh/AFxtZpb0/hzUiTWqdR6SWJF5FmRnOfFENWF1Q\n");
        cer.append("k8mgR5uM9iDBeQ4uFt4oTCRicGZe5kBLpyACN2B0cnUqRfR3wRv5xrFxMQ6QjrGG\n");
        cer.append("MDHMNHjdkaNWSmnC7EIgqW2iGltmmQWzwKfsES4Jcp+DEOfR4TqaUCxMNDHHDMKC\n");
        cer.append("XkSN5kw3YJBGzpEq6PqM56JCE6/fjdKL9oNv/Ax/iFyMtnzzMawuSOogY9dAPfBo\n");
        cer.append("5a5wdcd2h2LG0ABLxlUWTyyYp7buNJlEjmWOYspsJCUBd5bn+n7W0wbyqTgw6G52\n");
        cer.append("7OZR7dhefGuXGewzXRcXI++kahWe0mZpgi4eKGppqMPD1xfRzG6trD6OomhIR0IH\n");
        cer.append("KYGvd1PcY9Bd+yIW0a4fSS/p83440A9IlnYBo4X8OwIDAQABo4HoMIHlMBIGA1Ud\n");
        cer.append("EwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUR3U64djMQ3mqKgpo3Yxq//GbbwQw\n");
        cer.append("HQYDVR0OBBYEFA1+/BxGodsDO0AIUGgnhkXjgoGqMA4GA1UdDwEB/wQEAwIBhjB/\n");
        cer.append("BgNVHR8EeDB2MHSgcqBwhm5odHRwOi8vY2Etcm9vdC1jcmwtZGFya2NhbS5zMy51\n");
        cer.append("cy1lYXN0LTEuYW1hem9uYXdzLmNvbS9jcmwvNDYyNGRiMWQtYjE2Ny00MmViLThk\n");
        cer.append("ZmItMmE4NjBhZTBlYjQ0L0lhd0NKc3kwd0ZuLmNybDANBgkqhkiG9w0BAQsFAAOC\n");
        cer.append("AgEAQ2Dlf+Yl36PKOjRH7XBJ0RzqOfi6cKTacZTZJ4xvQDIdDwpHdtcHqNoX+der\n");
        cer.append("5jGieCw6axDFlAtTtymQESOgGz0TyYQK2PsWhEJPQfV9gWg1DICOoWs5tLWZJNqS\n");
        cer.append("NrjeOM1mcnSH2BbnwlZwiZ7tqsnH4o/3tOef/Wy7r+5GJqFCfPKB+ncUdSM2eVuu\n");
        cer.append("EEqIijn4jCg9qXQo7hbeY3B7MSo7Hp73kbg/jPR3Ek0BBviE0DrVUO6nbhkmKrUw\n");
        cer.append("U6khSiv9GMijdn+Q1EOBt00nZZfGfQLnAjF6Ebj8k0/jsnwLH9rzL5zjthV2dViX\n");
        cer.append("nrOlFRsNIGZtU22q8NtrjhfovYoEv3jF+GqvP6xVjsQtvaX7Ln7wMI5J9se+A6yE\n");
        cer.append("7EKnRcgW1r9FWAIwc2ykD4TPnSPjeJJXN1j2N4aIllO2WpDVnSV40s/p7K8MvuZt\n");
        cer.append("jrTTmKSWhdhCpqmexi53cl0hwghtwUpFrgqwxiYDu5on2JDqm9t8HLEkvI+EPhKh\n");
        cer.append("q8zn589ZccZ28vwecsIACqu0PIFFqiMGV30C2OVK+rC2PaaL03ttmkkX2lphVSiH\n");
        cer.append("lMDECwAk+35qlC+T0JPmg3v96VRQXGodnQj7GkOww6cbaatO/AscFiHpQteYjlw9\n");
        cer.append("PdQfRiLRAtr2lKMnmB/HAbyqVZrUxBGgI7azU5gQ+T0q8ow=\n");
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
