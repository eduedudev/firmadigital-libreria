/*
 * Copyright (C) 2026
 * Authors: Misael Fernández, CORPNEWBEST CIA. LTDA.
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
package ec.gob.firmadigital.libreria.certificate.ec.corpnewbest.cert;

import ec.gob.firmadigital.libreria.certificate.base.RubricaCertificate;

/**
 * Certificado raiz representado como un objeto
 * <code>X509Certificate</code>.<br>
 * emitido por CORPNEWBEST CIA. LTDA.
 *
 * @author Misael Fernández, CORPNEWBEST CIA. LTDA.
 */
public class CaCertCorpNewBest extends RubricaCertificate {

    private static final StringBuilder stringBuilder;

    public CaCertCorpNewBest() {
        super(stringBuilder);
    }

    static {
        stringBuilder = new StringBuilder();
        stringBuilder.append("-----BEGIN CERTIFICATE-----\n");
        stringBuilder.append("MIIGWDCCBECgAwIBAgIUBTK4CcsDoDjTUyPuoWbR9KCHb6QwDQYJKoZIhvcNAQEN\n");
        stringBuilder.append("BQAwgZsxOTA3BgNVBAMMMEFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFJBSVog\n");
        stringBuilder.append("Q0EtMSBDT1JQTkVXQkVTVDEwMC4GA1UECwwnRU5USURBRCBERSBDRVJUSUZJQ0FD\n");
        stringBuilder.append("SU9OIERFIElORk9STUFDSU9OMR8wHQYDVQQKDBZDT1JQTkVXQkVTVCBDSUEuIExU\n");
        stringBuilder.append("REEuMQswCQYDVQQGEwJFQzAeFw0yMzExMTgxMzM0MTBaFw0zMzA2MTIyMzU5NTla\n");
        stringBuilder.append("MIGbMTkwNwYDVQQDDDBBVVRPUklEQUQgREUgQ0VSVElGSUNBQ0lPTiBSQUlaIENB\n");
        stringBuilder.append("LTEgQ09SUE5FV0JFU1QxMDAuBgNVBAsMJ0VOVElEQUQgREUgQ0VSVElGSUNBQ0lP\n");
        stringBuilder.append("TiBERSBJTkZPUk1BQ0lPTjEfMB0GA1UECgwWQ09SUE5FV0JFU1QgQ0lBLiBMVERB\n");
        stringBuilder.append("LjELMAkGA1UEBhMCRUMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCZ\n");
        stringBuilder.append("A0t1w85jpbuu+Okq2sqEScoCb5PwpzgSYBYkUC5l+NfB+lg8/XD0gNfBG5Zp6PIV\n");
        stringBuilder.append("DeH8WJq+qku8SfTLM4hfkWoQBCwtGv8vmkBrB+LcdF5dDRVDgk3N5MrwnOHIUmOW\n");
        stringBuilder.append("i8hqnxEXjT+FALJTXK1xy1UWvdm8nx8DKPgP/aF2mn+NrijgJnK4FcJvzPl4+0sz\n");
        stringBuilder.append("kjvwpom7g7WgxPn3uRK0GWEE7OLEwDTQwyNRQXV1QrCYzgJxPsoHR6Ip5LDGWHO8\n");
        stringBuilder.append("RH8ZN5xq+58igX3kBpAfsr4++o565coic4if8Ml6fF984Stl+UkpgqcHGH785Q13\n");
        stringBuilder.append("gAGu5lZ5X+PBv0ju9hZXLOOyogYtJHHyD6J92cI/hHpMSXYzWHtjcjL5B67wOg+5\n");
        stringBuilder.append("c1E268QEq7wQm5+CaCFHplEZ/LlcL/ftIhcAtjJwTX573JiuuGPf/7Yk0TS/5G72\n");
        stringBuilder.append("/SzK0KkjZ6RHk142g0vBO6ETvXqbouIhrqJYg/srYU4z6ObQRZ+SujO5ZImDngnv\n");
        stringBuilder.append("P/m82QtKP132bfpcG/qqXnL0CjILfQh9VuoZDELK/uVoqWyCQ4yjojZf8ay1EvE8\n");
        stringBuilder.append("/p1ZNPQQ81+feTXLSw7y5l91wCwGazo9kRNMScOUB11A2Iyjci58xHng3NUNhYwi\n");
        stringBuilder.append("CXDzTFpQEVQE5m7DZDnqWwDF47/Y0RhzMRAQ4IwK2wIDAQABo4GRMIGOMA8GA1Ud\n");
        stringBuilder.append("EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUe37bqEq1Y5IUiIm/1BJx5vdkha4wHQYD\n");
        stringBuilder.append("VR0OBBYEFHt+26hKtWOSFIiJv9QSceb3ZIWuMCsGA1UdEAQkMCKADzIwMjMxMTE4\n");
        stringBuilder.append("MTMzNDEwWoEPMjAzMjEyMTQxMzQwMTBaMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG\n");
        stringBuilder.append("9w0BAQ0FAAOCAgEAbbO3YFgirRa9skdV+JkCc+VuFTYFc8y5YzXwbiZ4OV9nzY7p\n");
        stringBuilder.append("f+pHAroBiDThHeqgjfjjF0SAL32q+sJbc1SZyJSsz2Bvxi9vdXizKYxnstQPrSfk\n");
        stringBuilder.append("AidnLCUM384k5URl8/3M5ur4DuTTeLnEQRNkv6NUN9aCsIbZzhrEW7l1HoPJvrP6\n");
        stringBuilder.append("KfZRkJg01bfcPGjF/i5X4WaMi61w/aBm+fhNmFYe2/E5qTd5nbjSLVaqjZeysHtT\n");
        stringBuilder.append("KcM/dyKS4hB0A2HD0Q08IFPK243NIsHyiIe81gIy0tLdRP0mHqwN+pMzkk1+J99a\n");
        stringBuilder.append("gpOLrXjBKvkYPTaNzBaPCSGqps0Zad/xGN0HzfbUkNndbE8BduZuSAFjUIow7nBK\n");
        stringBuilder.append("ouSBqblfzDPUFvXJPAzIgD7qmlh7nP1/ztV55N6YdLTplMNXzYoJ6PoUuPRXacL5\n");
        stringBuilder.append("C/syRFVIcARp0DZhd9ltecY2jK6k8AuRu7cXAWejuXvrFxBu4dqK4ny93nThsVhM\n");
        stringBuilder.append("uecdxAu7a+4VWcB/pXwz90nxVETdGJ7fLGi4YU3eGy2eJjtUHx5K3dpItmcgpeV0\n");
        stringBuilder.append("ru5X1ICwYaxK4/w8Tt08NVeGL5vJMo34LkqkMU4rzpQeW1KMQGlbudVk8zJgFbHF\n");
        stringBuilder.append("o428plQvXJgZpWLH/wXA/1tFMGYApzlLCTrnaRZlPTH8oq69L5jFKMmNGk8=\n");
        stringBuilder.append("-----END CERTIFICATE-----\n");
    }
}
