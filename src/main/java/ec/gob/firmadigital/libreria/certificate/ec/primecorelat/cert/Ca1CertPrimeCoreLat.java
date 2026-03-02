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
package ec.gob.firmadigital.libreria.certificate.ec.primecorelat.cert;

import ec.gob.firmadigital.libreria.certificate.base.RubricaCertificate;

/**
 * Certificado raiz de PRIMECORELAT, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class Ca1CertPrimeCoreLat extends RubricaCertificate {

    private static final StringBuilder stringBuilder;

    public Ca1CertPrimeCoreLat() {
        super(stringBuilder);
    }

    static {
        stringBuilder = new StringBuilder();
        stringBuilder.append("-----BEGIN CERTIFICATE-----\n");
        stringBuilder.append("MIIHdzCCBV+gAwIBAgIUVflFa7tPxMINdLmA8aMybjBLTIkwDQYJKoZIhvcNAQEL\n");
        stringBuilder.append("BQAwgbIxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        stringBuilder.append("BVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwG\n");
        stringBuilder.append("A1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3Jl\n");
        stringBuilder.append("IFJvb3QgQ0ExMRwwGgYDVQRhDBNWQVRFQy0xNzkzMjI0MzM5MDAxMB4XDTI2MDEz\n");
        stringBuilder.append("MDExMjMzOFoXDTM4MDEyNzExMjMzOFowgbIxCzAJBgNVBAYTAkVDMRIwEAYDVQQI\n");
        stringBuilder.append("DAlQSUNISU5DSEExDjAMBgNVBAcMBVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVM\n");
        stringBuilder.append("QVQgUy5BLlMuIEIuSS5DLjEeMBwGA1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9u\n");
        stringBuilder.append("MRwwGgYDVQQDDBNQcmltZSBDb3JlIFJvb3QgQ0ExMRwwGgYDVQRhDBNWQVRFQy0x\n");
        stringBuilder.append("NzkzMjI0MzM5MDAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmJ2o\n");
        stringBuilder.append("h2FfrvTpbzqaSTdyzSB/hxJI2nWMLLDMjlPtSR7ilSwyaQ7ChvBPYXistpelHRul\n");
        stringBuilder.append("Sf0PiuM85aQWQNTaPPpuNtkaIqWrf+ATjrhb9mjgCiUPBO9OG3fAaV+VtgOPH/aa\n");
        stringBuilder.append("ygbqZkKHMMgzpGqv/rt/if9fpdDFysw5UmABEaVO6Juz7Wy/cGB167Im5N4WUE40\n");
        stringBuilder.append("giBw1c1i7nNjM3nfaxMyYVAyMfeoJXamTFXS3SKMaSz3ttFLoC30t+XIjUCcaXkj\n");
        stringBuilder.append("T30qF7OO9YQ0RXW5wV9konuh410QL5g6/u1zsHKZ3Yrd3FrZPM0cVeVcvWdeM7hz\n");
        stringBuilder.append("SfOW0OMo/I7WQmX/fhja1e+Uq4RLG4AY6KDmvlV8KTAoSHC/Vj5KPe2CW+l+vFQ9\n");
        stringBuilder.append("ka6BgOJ0h2zINa7rjR8mWoPiGRGITl55oxpHFHTqWJ2K0kazBP/BxEIRIfPt9H0I\n");
        stringBuilder.append("uajE/SFN8WJeLKKGgUbVJm3q4tqCRXHsvDn4POmbQByhZ2sxoBIXS78jGx3RBfag\n");
        stringBuilder.append("6j++zA1sHs1ANj7WyWIWLp7tLiAVvkTRmCkh6prLoGAyw7+bzuwt/vvuEGQig8Wi\n");
        stringBuilder.append("o3jcaBB+4F8tr2Ti9yPwcW7WRoRVQA4uwp0fh4h1k2s8l33Sv7J3K2ggxxGifdAN\n");
        stringBuilder.append("Z39mvu6W/gXnjthOga1heYVDI0BY6WRfqfo6uqkCAwEAAaOCAYEwggF9MB0GA1Ud\n");
        stringBuilder.append("DgQWBBSQoZEvNSBZyLAZZpfOMZG4GZTwnTAfBgNVHSMEGDAWgBSQoZEvNSBZyLAZ\n");
        stringBuilder.append("ZpfOMZG4GZTwnTAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBAjAw\n");
        stringBuilder.append("BgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGNjYTEub25saW5lL2NybC9jYTEuY3Js\n");
        stringBuilder.append("MIHDBgNVHSAEgbswgbgwgbUGBFUdIAAwgawwNAYIKwYBBQUHAgEWKGh0dHBzOi8v\n");
        stringBuilder.append("d3d3LnByaW1lY29yZS5sYXQvcmVwb3NpdG9yeS9jcHMwdAYIKwYBBQUHAgIwaBpm\n");
        stringBuilder.append("RWwgcHJlc2VudGUgY2VydGlmaWNhZG8gZXMgZW1pdGlkbyBlbiBiYXNlIGEgbGFz\n");
        stringBuilder.append("IHBvbMOtdGljYXMgZGUgc2VndXJpZGFkIGRlIFBSSU1FQ09SRUxBVCBTLkEuUy4g\n");
        stringBuilder.append("Qi5JLkMuMB8GA1UdEQQYMBaBFGZpcm1hc0BwcmltZWNvcmUubGF0MA0GCSqGSIb3\n");
        stringBuilder.append("DQEBCwUAA4ICAQAE2nnsWfhEFlpvP1MqVHBWY+D8lohK2g+vvDcmTksQqhh6/2lO\n");
        stringBuilder.append("3QvnqpJvqOglg230bXtwzCvLT6NnHSbv0aGjD5Gl8Ryzc/WeocTguL45ybgBaOLT\n");
        stringBuilder.append("v60o4rmXUy8Es1WiE51wdXJDySt2KSaaxTe9KFTXsecRNXGaPTaUW60acVyhosQF\n");
        stringBuilder.append("m/fDVQHTshEWYiqRkczJsgbQA3pPxKY6ncu/d9le+fnJ8kk9L5XLyxutKP4hrgJC\n");
        stringBuilder.append("QRHnYue/f0s7hXWIuBemFQXSXqh7TNEH/pkPWAtNzmlynjxHZHWWlhQBJ3iqnc3o\n");
        stringBuilder.append("o/kt56MbPQXD1li6a8S51x3FY5pg4zFPg0reIgrOFfI5syO+CKzkbY1VY8zYAglv\n");
        stringBuilder.append("u58wefOMZiahLmvbeca+5vDDPQUysHvTFlXFgPJir8gKGepau9MJr6+TNsHEb9f/\n");
        stringBuilder.append("bgsnnqXLmOB+4Or9PynT+vD6rohkQzLW4AY8ycRoVq8yOftQhP4SSFRx6Os/71dH\n");
        stringBuilder.append("+LbwKfsLnAVhU/42m3toQdBf53vy7w0bEbGQ1kL0udnlBunIkJPCM9bzFqyeKlM1\n");
        stringBuilder.append("uhXsn2EC7RxxJahQm6E5v9sl9+Ife7d+Qo6iX6FqXxm/53n4wGhNS7wsT4XlUSkw\n");
        stringBuilder.append("Ynyi7zeeotr8iwRgeggQ0bKRl9IxvFTLKkwaPyZo2ollETVlczayKALngA==\n");
        stringBuilder.append("-----END CERTIFICATE-----\n");
    }
}
