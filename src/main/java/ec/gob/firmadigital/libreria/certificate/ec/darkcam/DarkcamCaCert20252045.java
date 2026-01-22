/*
 * Copyright (C) 2025
 * Authors: Misael Fernández, DARKCAM S.A.
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
 * Certificado raiz de DARKCAM S.A., representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author DARKCAM S.A.
 */
public class DarkcamCaCert20252045 extends X509Certificate {

    private final X509Certificate certificate;

    public DarkcamCaCert20252045() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIFnDCCA4SgAwIBAgIQTxZn/Nrp8NDvwl91DQ3PjDANBgkqhkiG9w0BAQsFADBo\n");
        cer.append("MQswCQYDVQQGEwJFQzEVMBMGA1UECgwMREFSS0NBTSBTLkEuMQwwCgYDVQQLDANQ\n");
        cer.append("S0kxEjAQBgNVBAgMCVBpY2hpbmNoYTEQMA4GA1UEAwwHQ0EgUm9vdDEOMAwGA1UE\n");
        cer.append("BwwFUXVpdG8wHhcNMjUxMDA2MDIzODU1WhcNNDUxMDA2MDMzNzMzWjBoMQswCQYD\n");
        cer.append("VQQGEwJFQzEVMBMGA1UECgwMREFSS0NBTSBTLkEuMQwwCgYDVQQLDANQS0kxEjAQ\n");
        cer.append("BgNVBAgMCVBpY2hpbmNoYTEQMA4GA1UEAwwHQ0EgUm9vdDEOMAwGA1UEBwwFUXVp\n");
        cer.append("dG8wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCyK4fOlGGaR9tAEkAT\n");
        cer.append("COEhvRtpzEBmusqX6OQwqbIpXU3KeIORMTVdK13x52UhP7z4BNzzfI7BLEXPFfk1\n");
        cer.append("7DicrAFwFmppueyeKk5ZjGIRfRbpbXgae4N5bQX9NiKnuXEbkJQ9NufHvsoWD6LX\n");
        cer.append("M2GwBam3mUa4q4Jh/s/3cpf96GZncWO0aSuI2hAdNPdooX9Lhy+yTjoN/SUKp4vt\n");
        cer.append("agma10gkW27A5lJ7nGwE/HvL8YmrudFB3FPlY9pFUwpjgv7U8mtwRVq809ASnwtF\n");
        cer.append("/9fkGeL5RHIGq/B/4OD4WAsInDWy1PD56+ZTPGO1bq+mzEGWCLj9oAckAvnSTQLT\n");
        cer.append("wflblZRmPLvO4H5Z1b6bUZ8uXKcgO1U9aMZhxebjuRfFACmdLYuzr61Pfqdsjop3\n");
        cer.append("gAoGI/KH4G6ocDE9Z+wc9Q06S9/1YvvisQcVd9XWn1LnuIBHd/DYl/GjO8pN28Eq\n");
        cer.append("ao9RDdgWAB5qCW26QdVrjTyuRHj80T8QBTfv+zwrOYt4dO43uAayEpmUUmerY3CS\n");
        cer.append("DOCzkb3RAqvoox6pRL4GDcZLLKOut58UUi1AJ7wlNCqeIuTcLGuFNW8u2Ne+3h9i\n");
        cer.append("BtoPjsIj43BEj+tOADTULHwACff610u7hlqlR7EcNRgVXFSsFMJApRvEHJ8euAMF\n");
        cer.append("4oO1OpOxJ9m+9L5mW8cSR2JxLwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0G\n");
        cer.append("A1UdDgQWBBRHdTrh2MxDeaoqCmjdjGr/8ZtvBDAOBgNVHQ8BAf8EBAMCAYYwDQYJ\n");
        cer.append("KoZIhvcNAQELBQADggIBADMPLHkU5c0iT1IcnYVhGD7Eaw3zJWWeKSCm/97EiI2Y\n");
        cer.append("nNU1E4x7bBKrRiWoDYXvZSmdcbjhP1bSW7QOpU+8bHUz9Vx0muopROllQ8YiidN9\n");
        cer.append("4djnAv4GBVoAATw253WxksyYd9nxYrDt147HDsWJ8xFUELz2yHHidHPjj/9APo4Y\n");
        cer.append("TT33cdbP6REgWCLvZj6yCd1ZxJITU3z+68SqVPxsNoyDZdX3yLNOMh9z8Ya8b0b8\n");
        cer.append("zgI/JgeKh1V8PdkBZkoK+8PyAWl5Y50kSve51WTDLu8BKjl3DqFe/A8xJIWs0dF+\n");
        cer.append("AIe8q4RM4Dr/piT6GohBzej1Gj1mT3mgLtmlkU9dt2ngPsPt1GUexrULDV/YdTuV\n");
        cer.append("hdvBzQcU87EKsMtcLLWM0wE6P78ySRzzgGqFBDGsG5358T9PuZ2e+ZnD8iodJTYE\n");
        cer.append("WF/4+O71fDDYejsNol8Bl1+TxLCeFnQxuJDw7W0e+KyDE/fu7NiYAClWPqVOMRcB\n");
        cer.append("vJ7lwzOaYfwIvesJcTbHyvfaxkov9+LGdmefAHq9XCl23b6Ky9zOh4vzjG2C+Nqt\n");
        cer.append("P2FhaP60IkDlTbJyt6RJIEfV5KXQAThdMNbDAGwFH0vb3swh+aeWl7TZ5Bs6+rHD\n");
        cer.append("RShtZEop03pwQv7KTyAVaxMupEJkufIyoBXS92WvcaoB9C18NWy0vmy2Toy7Cvco\n");
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
