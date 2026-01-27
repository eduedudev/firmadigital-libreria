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
        cer.append("MIIFezCCA2OgAwIBAgIUFOa8/46YtLq4VXk/BTZtDB9dKhMwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgZQxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwG\n");
        cer.append("A1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3Jl\n");
        cer.append("IFJvb3QgQ0EyMB4XDTI2MDEyMjIxMzg0N1oXDTM4MDExOTIxMzg0N1owYjELMAkG\n");
        cer.append("A1UEBhMCRUMxIzAhBgNVBAoMGlBSSU1FQ09SRUxBVCBTLkEuUy4gQi5JLkMuMR4w\n");
        cer.append("HAYDVQQDDBVQcmltZSBDb3JlIEVtaXNvciBDQTIxDjAMBgNVBAcMBVFVSVRPMIIB\n");
        cer.append("IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7nPh/5V1chAYxGb50cyR9+4p\n");
        cer.append("IiXYuHeT1kj9kAYl8ItR2r7m0XCmsqVZtM7t7hx5SuJNW+L5WwF99x8347NKiuwY\n");
        cer.append("BRaakWksTijy5t/dpC+OZcG/bSbceLa6JdJba6S9pFrXGWmJ7lxjEozfSeyZ7RiN\n");
        cer.append("KdySW65qWydAnGreVcrX2/Che1zXNYhxu1dY+ycj4gf5gXM7cyLErOI4HVdbVU2s\n");
        cer.append("YdG8rOElRLD/EsUI51J6M+BHDXql32am8Dt/Kqdb3JkOLSN1qa0XSET8hlhitK19\n");
        cer.append("d82g1HyApwSRvGospfxdvUmc0S3VOQhxCfaG8FTVjod3ECF63G9gGxVZavqXvQID\n");
        cer.append("AQABo4H1MIHyMB0GA1UdDgQWBBTCVGTMZt2HrGEIWym28smyyXA6/DAfBgNVHSME\n");
        cer.append("GDAWgBT/9jk45u8/q9CdG0dLR6q4tbwvRDASBgNVHRMBAf8ECDAGAQH/AgEAMA4G\n");
        cer.append("A1UdDwEB/wQEAwIBhjAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGNjYTIub25s\n");
        cer.append("aW5lL2NybC9jYTIuY3JsMDkGCCsGAQUFBwEBBC0wKzApBggrBgEFBQcwAYYdaHR0\n");
        cer.append("cDovL3BjY2EyLm9ubGluZTozMDQ0L29jc3AwHwYDVR0RBBgwFoEUZmlybWFzQHBy\n");
        cer.append("aW1lY29yZS5sYXQwDQYJKoZIhvcNAQELBQADggIBAFszlnKs3F7If73jV3EcGHBS\n");
        cer.append("fAx12z/kqRZWsPyfykz+zfMMPBrwcgDG7vYl+qwIBfKTg3DJZSuRVOonF5w/arZ1\n");
        cer.append("h5lOl8/QjwvEb0yFkX685dsk6rwYWhcGQ2g/TNWhlfRdgHmRJNz9qqhBlhB6chWt\n");
        cer.append("WKISa4ub7pFfJiesnb2epPo/ZwvcLWSHMIeqr5bj6ZzjPaOlH72rKY+a9NyN/A7G\n");
        cer.append("fys/RUnXeW3pwdSEY8a2uE0WJjtGkfCRD/LyMoWWoGx6C7PJrEZJZuFYzLlV5CtZ\n");
        cer.append("iFFlWljZwb5hwKuhICa+0KQ46qbs1C4fZMMkEi/NLVTLSdm8dKc1hkVRrne+8FBV\n");
        cer.append("MKLAf3X+ssIJh6jmz+R8kUxTJiIyxjCeA/+e3vhrdHM/J6xaRlUh15IRmf4D3EEa\n");
        cer.append("Jbfz5lCEgIOMl6KC9nEou0KeDeQ75SdAHeMg4Z5coTayBpMWxEpBBBvauWiqZeVp\n");
        cer.append("MPdHay5BOXm5ctDsO8zA4GLierYMW1H8YSF/n+97VDRczFqCP0FbUzmRCo3MUhIL\n");
        cer.append("0G0ofAcvXS3HCdmw1a3ftaW8600+22QjVsAWWhXtT1VRb/mlueXe/5mpWqv48QF8\n");
        cer.append("XNSW7yuiDPMDSZqjKLNdNcvszuAEBPU0qLn2CPN6pheM0mTiRLD+OQeVd0qajLFR\n");
        cer.append("gtxLDkR1gNFxT60oz1a+\n");
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
