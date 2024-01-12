/*
 * Copyright (C) 2024
 * Authors: Mauricio Perez
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
package ec.gob.firmadigital.libreria.certificate.ec.firmasegura;

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
 * Certificado intermedio del Firmasegura S.A.S., representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Mauricio Perez <mauricio.perez@firmaseguraec.com>
 */
public class FirmaSeguraSubCaCert20232043 extends X509Certificate {

    private X509Certificate certificate;

    public FirmaSeguraSubCaCert20232043() {
        super();

        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("-----BEGIN CERTIFICATE-----\n");
        stringBuilder.append("MIIGeTCCBGGgAwIBAgIRANKNJ7kdAp3D4bHeEon0FtUwDQYJKoZIhvcNAQELBQAw\n");
        stringBuilder.append("gcQxCzAJBgNVBAYTAkVDMRswGQYDVQQKDBJGSVJNQVNFR1VSQSBTLkEuUy4xMDAu\n");
        stringBuilder.append("BgNVBAsMJ0VOVElEQUQgREUgQ0VSVElGSUNBQ0lPTiBERSBJTkZPUk1BQ0lPTjET\n");
        stringBuilder.append("MBEGA1UECAwKVFVOR1VSQUhVQTFAMD4GA1UEAww3QVVUT1JJREFEIERFIENFUlRJ\n");
        stringBuilder.append("RklDQUNJT04gUkFJWiBDQS0xIEZJUk1BU0VHVVJBIFMuQS5TLjEPMA0GA1UEBwwG\n");
        stringBuilder.append("QU1CQVRPMB4XDTIzMTIyNzE4NDYyM1oXDTQzMTIyMDE5NDM1N1owgcIxCzAJBgNV\n");
        stringBuilder.append("BAYTAkVDMRswGQYDVQQKDBJGSVJNQVNFR1VSQSBTLkEuUy4xMDAuBgNVBAsMJ0VO\n");
        stringBuilder.append("VElEQUQgREUgQ0VSVElGSUNBQ0lPTiBERSBJTkZPUk1BQ0lPTjETMBEGA1UECAwK\n");
        stringBuilder.append("VFVOR1VSQUhVQTE+MDwGA1UEAww1QVVUT1JJREFEIERFIENFUlRJRklDQUNJT04g\n");
        stringBuilder.append("U1VCQ0EtMSBGSVJNQVNFR1VSQSBTLkEuUy4xDzANBgNVBAcMBkFNQkFUTzCCAiIw\n");
        stringBuilder.append("DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALPVPM8X7l/IlZT+rGnN8y2MuSpy\n");
        stringBuilder.append("QiENKHy+sAtrOgpE6JaA9S6L4M4KlsL5va2isWl9+Q8ogp2K8rjpHyjNGB2jpPd6\n");
        stringBuilder.append("3HaAJ0K/zZ6KqzdRIX35EtS0X1IgUSFkssCwG8AIKpSWvkjoWpGlN1TlTl0U6IBL\n");
        stringBuilder.append("B282DmkHGHm4Fah9C8m7uHkZakeAvOt6S+oKgxEqcopkZHvqs/C/NVn1u/JSblDV\n");
        stringBuilder.append("7tBrDga9b1ejvkErokczE1f/vDSMYO2hJ+3LHtHnQEiKUOP0k1CDcDmP/KglXXH5\n");
        stringBuilder.append("KVdoMOrBgkwPqijNnIRabguohcMvrndR8nUKCbpuciapmrSuevF4ZLUFavZyk/Wg\n");
        stringBuilder.append("iBbJiKtpYtpZZok4N01oJhAqB1zN4jJ/LuOnKmH0EVe0swvpl+TjJ2sptSW9qyF+\n");
        stringBuilder.append("tx781Z0eEJoVcj1vuPOowjzpVEkCcmXgUQWtoiXyyWJOEjvebhB2RPiXXIjORU0I\n");
        stringBuilder.append("utlDyEIxwedI0iwlSM8E9uTM9/kgqXDsvvrDNY/nt3Jv1Z0rQpfgvIoqYeb8Q3Ll\n");
        stringBuilder.append("NDV2q1ro1u76u7lpg4/P3Y9v2rp8l5hO2S8C6DReBv0q1lC6WF2gQTfKPtUtu1Y+\n");
        stringBuilder.append("7ZMQM85jzCu4lBLLQE1jCnkeGwZ31SQPLAYYor40MtgqlMj5gCBRrWWVJGVH7tad\n");
        stringBuilder.append("GYgqmV5zC/u+QUbRAgMBAAGjZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0j\n");
        stringBuilder.append("BBgwFoAUE3QO85otcvosx6bXbt7CII960DMwHQYDVR0OBBYEFBNGk2gJrtckhzNF\n");
        stringBuilder.append("YyZ336xeXopRMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAe0Ye\n");
        stringBuilder.append("dWe+shh4K7iqSEBzKXHhizZufOExcf8W1kEnlhAGk9DkVcImA/Ulxkk+lSEAIugJ\n");
        stringBuilder.append("flLvdP+oisu7IJZC0m7S5HsaeHZJCQ8lrridm41ymq7RU+yU3Ka7cwxegOHUPMfF\n");
        stringBuilder.append("v5odBwMJpgFbTnl6xP/5lXrzZQhQMXFmH0coKgdjFJrYVTBqehAFz9RnE4tQ41P4\n");
        stringBuilder.append("I6gjavicOXN1tnkEtxtul4fCsFgpU19821IwOMDxVsumPkzFm0pb2A8BsCGgcIMm\n");
        stringBuilder.append("i2HmjxeWMCRkUKpK2Pt4a+v0gidToCLrpNHBvIuIs9lhvLIJf60Ha2QAKLTuPa66\n");
        stringBuilder.append("SbRC6g5vT5bOxq+vtJNqFeBf694s+VYcji3pCZAxwr6c/an3GZU8ZTIBW1MXussR\n");
        stringBuilder.append("5Ex1bl9T5lzuH9T4ivsMt6u4nKyfEbBFq5Hl5w4B2yAhuCDXfd6lzhdWNtxL3pUH\n");
        stringBuilder.append("AyGZqQ5GpYNuJI5rtyyligoap0tubQT3Skd9uB1LOQpkl83prZMK1RmEBuLUM6w6\n");
        stringBuilder.append("VPrrDAFO9JE8cfwrsy3atQ7kjaZflLmqpBbB0zLuy05N0QaERj3kB0ImxGp5ZBoN\n");
        stringBuilder.append("1j23zSOesqLcEyvDga8a9wNENWQ5Idw6RhP2pIg9EJ349G4umzcYdeJKDtukAV6J\n");
        stringBuilder.append("O10wk7XZO79ZwCMjIkIAM5JsyrI663X/kwu7LVU=\n");
        stringBuilder.append("-----END CERTIFICATE-----\n");

        try {
            InputStream is = new ByteArrayInputStream(stringBuilder.toString().getBytes("UTF-8"));
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
