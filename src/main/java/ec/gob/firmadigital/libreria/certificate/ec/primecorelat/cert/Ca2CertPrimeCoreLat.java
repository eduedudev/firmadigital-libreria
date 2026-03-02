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
public class Ca2CertPrimeCoreLat extends RubricaCertificate {

    private static final StringBuilder stringBuilder;

    public Ca2CertPrimeCoreLat() {
        super(stringBuilder);
    }

    static {
        stringBuilder = new StringBuilder();
        stringBuilder.append("-----BEGIN CERTIFICATE-----\n");
        stringBuilder.append("MIIHdzCCBV+gAwIBAgIUYULxZxrQodqQMNbR/fF8NfdsOHEwDQYJKoZIhvcNAQEL\n");
        stringBuilder.append("BQAwgbIxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        stringBuilder.append("BVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwG\n");
        stringBuilder.append("A1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3Jl\n");
        stringBuilder.append("IFJvb3QgQ0EyMRwwGgYDVQRhDBNWQVRFQy0xNzkzMjI0MzM5MDAxMB4XDTI2MDEz\n");
        stringBuilder.append("MDExMDUxNloXDTM4MDEyNzExMDUxNlowgbIxCzAJBgNVBAYTAkVDMRIwEAYDVQQI\n");
        stringBuilder.append("DAlQSUNISU5DSEExDjAMBgNVBAcMBVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVM\n");
        stringBuilder.append("QVQgUy5BLlMuIEIuSS5DLjEeMBwGA1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9u\n");
        stringBuilder.append("MRwwGgYDVQQDDBNQcmltZSBDb3JlIFJvb3QgQ0EyMRwwGgYDVQRhDBNWQVRFQy0x\n");
        stringBuilder.append("NzkzMjI0MzM5MDAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApChh\n");
        stringBuilder.append("6XcTrItx570j7MXnHMuHSj8P8OvyZz+UE8aoVgIFQuetgAQCXd0P810XTF1lGT5I\n");
        stringBuilder.append("mmoU1z7Gst+vQ2Uq/eukMp8GVDg0IWBc41Iso3osNwZiqinBygcfGYeesWyI5qeB\n");
        stringBuilder.append("EuiafIm1yVYoYr7GZE2dQsvPNr0v3+MQLf0r4GaqpkfZru1YPU0FeaelEUUYfmgS\n");
        stringBuilder.append("jLYCuDYoN7HtrgPrFgFwgfxgnTvE4V73866Uyvw7e3dTmInPbJew3qhyu0Fmz16U\n");
        stringBuilder.append("de4KIezwMj++aY4rKOM3KnIHguQUyQZrBNMjGhtJIqW6dU1qMZ8GNPQGcQpcIVW5\n");
        stringBuilder.append("spgifELl6DlrUWB4u+np7sYdqcOMz+VN11lG4bF4iDSpNBqAJ7btjO3rSBUuvejV\n");
        stringBuilder.append("TdU/Y/aTcQkAQSff8TU89GznrNgCP7CxhuUJoaVf+nephLNFme0r2j1F0madeWVy\n");
        stringBuilder.append("85KL0qmZqsmQf9F9P9Mk5s5FIniaWnAZ4EB0XFrF5fmozOrrdiE95Txzp4p6RsJf\n");
        stringBuilder.append("LqN+qqvVE+knDM0OnlljUz9UAP4N6pieUF7QoA8ck3ZD0UQH23RS4kpN5CvV32f7\n");
        stringBuilder.append("Ffu2Z8dnah7F1LGwUBwWfBNk7G9tVGCqmwiq4xsUjTYd751xzCR7z3/CK+kFmkfN\n");
        stringBuilder.append("FsE58L+bRnChdm9T5B5+prxYCNFI/pLzQRX7jsUCAwEAAaOCAYEwggF9MB0GA1Ud\n");
        stringBuilder.append("DgQWBBRc9/tMHCkqyWj1Ewd+bDdAzgp24DAfBgNVHSMEGDAWgBRc9/tMHCkqyWj1\n");
        stringBuilder.append("Ewd+bDdAzgp24DAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBAjAw\n");
        stringBuilder.append("BgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGNjYTIub25saW5lL2NybC9jYTIuY3Js\n");
        stringBuilder.append("MIHDBgNVHSAEgbswgbgwgbUGBFUdIAAwgawwNAYIKwYBBQUHAgEWKGh0dHBzOi8v\n");
        stringBuilder.append("d3d3LnByaW1lY29yZS5sYXQvcmVwb3NpdG9yeS9jcHMwdAYIKwYBBQUHAgIwaBpm\n");
        stringBuilder.append("RWwgcHJlc2VudGUgY2VydGlmaWNhZG8gZXMgZW1pdGlkbyBlbiBiYXNlIGEgbGFz\n");
        stringBuilder.append("IHBvbMOtdGljYXMgZGUgc2VndXJpZGFkIGRlIFBSSU1FQ09SRUxBVCBTLkEuUy4g\n");
        stringBuilder.append("Qi5JLkMuMB8GA1UdEQQYMBaBFGZpcm1hc0BwcmltZWNvcmUubGF0MA0GCSqGSIb3\n");
        stringBuilder.append("DQEBCwUAA4ICAQBIpLf3Gn+jhCfZvntKuj99oom7eS5860CSC610W8ewR8+HxB0+\n");
        stringBuilder.append("71g6EKSeYidBK4AypTYbffO8MVky4hHIxnDCN2vbGvQWkr2C7O8pnQ6EHMf72JrH\n");
        stringBuilder.append("s9HT641ofEYplWO3UzuxYU4veicScOWvU8jqjBUohVSxI2L7edE4iXyrNWeUYRAV\n");
        stringBuilder.append("JuJmbTpI3WC2Y2TSNGredTYbFBX3oupNa7G9jfjZQ4GoIPSL6nwPlUrIRlsGVbbK\n");
        stringBuilder.append("6r9kzOgNGXiQJp3R6wzJZ1uOdACguZp5MQp/jKsp7Ir7X/O0WVAHnf+x0gCOYLl6\n");
        stringBuilder.append("i7DmDlbGopXBREkzNFcy9CBBmgQiwSR728J21R2b+rTEAmXKm3iRzT7zSwzj4H7m\n");
        stringBuilder.append("S/vvNHkYBgLsQoCfZrp/cQA7Bw6ZgW7bESDT411+vkMnJ7sW5afe++n8y8mZl31C\n");
        stringBuilder.append("en60Ze0kk3uxcm9qdbrxXxQJed6YXPaC+GnSSIdGQheOgr9oCilwid9N6xoRRLAd\n");
        stringBuilder.append("abjz0leQsIpxY7BxpgmvBPAsEwAatOXFbuK5d5XUx//eYVEPZkhjed5cujuLH6MZ\n");
        stringBuilder.append("oSM7n9FJr7E3VO7M0mVsKwPn2pw7ZYeni+juMLnOPpNIxBpUZYHk6fAnh0UQOwpy\n");
        stringBuilder.append("UVm1WwwWMtStBdyWKWywDzewU60KSDhcGKlOzJjFMkQ7tBm212GmtrKoPA==\n");
        stringBuilder.append("-----END CERTIFICATE-----\n");
    }
}
