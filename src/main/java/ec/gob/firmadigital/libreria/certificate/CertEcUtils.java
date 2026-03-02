/*
 * Copyright (C) 2026 
 * Authors: Ricardo Arguello, Misael Fernández
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
package ec.gob.firmadigital.libreria.certificate;

import ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies.*;
import ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.anfac.*;
import ec.gob.firmadigital.libreria.certificate.ec.anfac.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.appfirmas.*;
import ec.gob.firmadigital.libreria.certificate.ec.appfirmas.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.argosdata.CertificadoDataFactoryArgosData;
import ec.gob.firmadigital.libreria.certificate.ec.argosdata.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.bce.*;
import ec.gob.firmadigital.libreria.certificate.ec.bce.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.cj.*;
import ec.gob.firmadigital.libreria.certificate.ec.cj.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.corpnewbest.*;
import ec.gob.firmadigital.libreria.certificate.ec.corpnewbest.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.darkcam.*;
import ec.gob.firmadigital.libreria.certificate.ec.darkcam.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.datil.*;
import ec.gob.firmadigital.libreria.certificate.ec.datil.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.digercic.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.eclipsoft.*;
import ec.gob.firmadigital.libreria.certificate.ec.firmasegura.*;
import ec.gob.firmadigital.libreria.certificate.ec.firmasegura.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.lazzate.*;
import ec.gob.firmadigital.libreria.certificate.ec.lazzate.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.letmi.*;
import ec.gob.firmadigital.libreria.certificate.ec.letmi.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.primecorelat.*;
import ec.gob.firmadigital.libreria.certificate.ec.primecorelat.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.securitydata.*;
import ec.gob.firmadigital.libreria.certificate.ec.securitydata.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.uanataca.CertificadoDataFactoryUanataca;
import ec.gob.firmadigital.libreria.certificate.ec.uanataca.cert.*;

import ec.gob.firmadigital.libreria.certificate.to.DatosUsuario;
import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import java.security.cert.X509Certificate;

/**
 * Validar diferentes certificados digitales acreditados por ARCOTEL
 *
 * @author Misael Fernández
 */
public class CertEcUtils {

    public static final String ALPHATECHNOLOGIES_NAME = "ALPHA TECHNOLOGIES CIA. LTDA.";
    public static final String ANFAC_NAME = "ANFAC AUTORIDAD DE CERTIFICACION ECUADOR C.A.";
    public static final String APPFIRMAS_NAME = "APPFIRMAS S.A.";
    public static final String AGOSDATA_NAME = "ARGOSDATA CERTIFICACIÓN DE INFORMACIÓN Y SERVICIOS RELACIONADOS S.A.S.";
    public static final String AGOSDATA_NAME_OLD = "ARGOSDATA CA";
    public static final String BCE_NAME = "BANCO CENTRAL DEL ECUADOR";
    public static final String CJ_NAME = "CONSEJO DE LA JUDICATURA";
    public static final String CORPNEWBEST_NAME = "CORPNEWBEST CIA. LTDA.";
    public static final String DARKCAM_NAME = "DARKCAM S.A.";
    public static final String DATIL_NAME = "DATILMEDIA S.A.";
    public static final String DIGERCIC_NAME = "DIRECCIÓN GENERAL DE REGISTRO CIVIL, IDENTIFICACIÓN Y CEDULACIÓN";
    public static final String ECLIPSOFT_NAME = "ECLIPSOFT S.A.";
    public static final String FIRMASEGURA_NAME = "FIRMASEGURA S.A.S.";
    public static final String LAZZATE_NAME = "LAZZATE CIA. LTDA";
    public static final String LETMI_NAME = "LETMI ECUADOR S.A.";
    public static final String PRIMECORELAT_NAME = "PRIMECORELAT S.A.S. B.I.C.";
    public static final String SECURITYDATA_NAME = "SECURITY DATA SEGURIDAD EN DATOS Y FIRMA DIGITAL S.A.";
    public static final String SECURITYDATA_NAME_OLD = "SECURITY DATA";
    public static final String UANATACA_NAME = "UANATACA ECUADOR S.A.";
    public static final String UANATACA_NAME_OLD = "UANATACA S.A.";

    public static X509Certificate getRootCertificate(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        switch (getNombreCA(certificado)) {
            case ALPHATECHNOLOGIES_NAME: {
                try {
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertAlphaTechnologies20232026())) {
                        System.out.println("AlphaTechnologiesSubCaCert 2023-2026");
                        return new SubCaCertAlphaTechnologies20232026();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertAlphaTechnologies20242032())) {
                        System.out.println("AlphaTechnologiesSubCaCert 2024-2032");
                        return new SubCaCertAlphaTechnologies20242032();
                    }
                    return null;
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            case ANFAC_NAME:
                try {
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertAnfAc20162032_18332())) {
                        System.out.println("Anf 2016-2032");
                        return new SubCaCertAnfAc20162032_18332();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertAnfAc20192029_37442())) {
                        System.out.println("Anf 2019-2029");
                        return new SubCaCertAnfAc20192029_37442();
                    }
                    return null;
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            case APPFIRMAS_NAME: {
                try {
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertAppFirmas20252050())) {
                        System.out.println("AppFirmasSubCaCert2025-2050");
                        return new SubCaCertAppFirmas20252050();
                    }
                    return null;
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            case AGOSDATA_NAME: {
//                return new SubCaCertArgosData();
            }
            case AGOSDATA_NAME_OLD: {
                return new SubCaCertArgosData();
            }
            case BCE_NAME: {
                try {
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertBce20112021())) {
                        System.out.println("BceSubCaCert 2011-2021");
                        return new SubCaCertBce20112021();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertBce20192029())) {
                        System.out.println("BceSubCaCert 2019-2029");
                        return new SubCaCertBce20192029();
                    }
                    return null;
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            case CJ_NAME:
                return new SubCaCertConsejoJudicatura();
            case CORPNEWBEST_NAME: {
                try {
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCa1CertCorpNewBest20232033())) {
                        System.out.println("CorpNewBestSubCa1Cert");
                        return new SubCa1CertCorpNewBest20232033();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCa2CertCorpNewBest20232033())) {
                        System.out.println("CorpNewBestSubCa2Cert");
                        return new SubCa2CertCorpNewBest20232033();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCa3CertCorpNewBest20232033())) {
                        System.out.println("CorpNewBestSubCa3Cert");
                        return new SubCa3CertCorpNewBest20232033();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCa1CertCorpNewBest2024011020330619())) {
                        System.out.println("CorpNewBestSubCa1_2024011020330619Cert");
                        return new SubCa1CertCorpNewBest2024011020330619();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCa2CertCorpNewBest2024011020330619())) {
                        System.out.println("CorpNewBestSubCa2_2024011020330619Cert");
                        return new SubCa2CertCorpNewBest2024011020330619();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCa3CertCorpNewBest2024011020330619())) {
                        System.out.println("CorpNewBestSubCa3_2024011020330619Cert");
                        return new SubCa3CertCorpNewBest2024011020330619();
                    }
                    return null;
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            case DARKCAM_NAME: {
                try {
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaShortCertDarkcam20262036())) {
                        System.out.println("DarkcamSubCaShortCert2026-2036");
                        return new SubCaShortCertDarkcam20262036();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertDarkcam20262036())) {
                        System.out.println("DarkcamSubCaCert2026-2036");
                        return new SubCaCertDarkcam20262036();

                    }
                    return null;
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            case DATIL_NAME: {
                return new SubCaCertDatil20212031();
            }
            case DIGERCIC_NAME: {
                return new SubCaCertDigercic20212031();
            }
            case FIRMASEGURA_NAME: {
                try {
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertFirmaSegura20232043())) {
                        System.out.println("FirmaSeguraSubCaCert2023-2043");
                        return new SubCaCertFirmaSegura20232043();
                    }
                    return null;
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            case LAZZATE_NAME: {
                try {
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertLazzate())) {
                        System.out.println("LazzateCA 2022-2037");
                        return new SubCaCertLazzate();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCa1CertLazzate())) {
                        System.out.println("LazzateCA1 2023-2053");
                        return new SubCa1CertLazzate();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCa2CertLazzate())) {
                        System.out.println("LazzateCA2 2023-2053");
                        return new SubCa2CertLazzate();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaWeGoCertLazzate())) {
                        System.out.println("LazzateCAWeGo 2023-2053");
                        return new SubCaWeGoCertLazzate();
                    }
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            case LETMI_NAME: {
                try {
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertLetmi20252035())) {
                        System.out.println("LetmiSubCaCert2025-2035");
                        return new SubCaCertLetmi20252035();
                    }
                    return null;
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            case PRIMECORELAT_NAME: {
                try {
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCa1CertPrimeCoreLat20262036())) {
                        System.out.println("PrimeCoreLatCA1 2026-2036");
                        return new SubCa1CertPrimeCoreLat20262036();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCa2CertPrimeCoreLat20262036())) {
                        System.out.println("PrimeCoreLatCA2 2026-2036");
                        return new SubCa2CertPrimeCoreLat20262036();
                    }
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            case SECURITYDATA_NAME: {
                try {
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertSecurityData20112026())) {
                        System.out.println("SecurityDataSubCaCert");
                        return new SubCaCertSecurityData20112026();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertSecurityData20192031())) {
                        System.out.println("SecurityDataSubCaCert 2019-2031");
                        return new SubCaCertSecurityData20192031();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertSecurityData20202039())) {
                        System.out.println("SecurityDataSubCaCert 2020-2032");
                        return new SubCaCertSecurityData20202039();
                    }
                    return null;
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            case SECURITYDATA_NAME_OLD: {
                try {
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertSecurityData20112026())) {
                        System.out.println("SecurityDataSubCaCert");
                        return new SubCaCertSecurityData20112026();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertSecurityData20192031())) {
                        System.out.println("SecurityDataSubCaCert 2019-2031");
                        return new SubCaCertSecurityData20192031();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertSecurityData20202039())) {
                        System.out.println("SecurityDataSubCaCert 2020-2032");
                        return new SubCaCertSecurityData20202039();
                    }
                    return null;
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            case UANATACA_NAME: {
//                try {
//                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertUanataca0120162029())) {
//                        System.out.println("Uanataca 2016-2029");
//                        return new SubCaCertUanataca0120162029();
//                    }
//                    return null;
//                } catch (java.security.InvalidKeyException ex) {
//                    //TODO
//                }
            }
            case UANATACA_NAME_OLD: {
                try {
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertUanataca0120162029())) {
                        System.out.println("Uanataca 2016-2029");
                        return new SubCaCertUanataca0120162029();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertUanataca0220162029())) {
                        System.out.println("Uanataca 2016-2029");
                        return new SubCaCertUanataca0220162029();
                    }
                    if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertUanataca0320212034())) {
                        System.out.println("Uanataca 2021-2034");
                        return new SubCaCertUanataca0320212034();
                    }
                    return null;
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            default:
                throw new EntidadCertificadoraNoValidaException("Entidad Certificadora no reconocida");
        }
    }

    public static String getNombreCA(X509Certificate certificado) {
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(ALPHATECHNOLOGIES_NAME)) {
            return ALPHATECHNOLOGIES_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(ANFAC_NAME)) {
            return ANFAC_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(APPFIRMAS_NAME)) {
            return APPFIRMAS_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(AGOSDATA_NAME_OLD)) {
            return AGOSDATA_NAME_OLD;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(AGOSDATA_NAME)) {
            return AGOSDATA_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(BCE_NAME)) {
            return BCE_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(CJ_NAME)) {
            return CJ_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(CORPNEWBEST_NAME)) {
            return CORPNEWBEST_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(DARKCAM_NAME)) {
            return DARKCAM_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(DATIL_NAME)) {
            return DATIL_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(DIGERCIC_NAME)) {
            return DIGERCIC_NAME;
        }
//        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(ECLIPSOFT_NAME)) {
//            return ECLIPSOFT_NAME;
//        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(FIRMASEGURA_NAME)) {
            return FIRMASEGURA_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(LAZZATE_NAME)) {
            return LAZZATE_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(LETMI_NAME)) {
            return LETMI_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(PRIMECORELAT_NAME)) {
            return PRIMECORELAT_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(SECURITYDATA_NAME)) {
            return SECURITYDATA_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(SECURITYDATA_NAME_OLD)) {
            return SECURITYDATA_NAME_OLD;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(UANATACA_NAME)) {
            return UANATACA_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(UANATACA_NAME_OLD)) {
            return UANATACA_NAME_OLD;
        }
        return "Entidad no reconocida " + certificado.getIssuerX500Principal().getName();
    }

    public static DatosUsuario getDatosUsuarios(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        switch (getNombreCA(certificado)) {
            case ALPHATECHNOLOGIES_NAME -> {
                return CertificadoDataFactoryAlphaTechnologies.getDatosUsuarioAlphaTechnologies(certificado);
            }
            case ANFAC_NAME -> {
                return CertificadoDataFactoryAnfAc.getDatosUsuarioAnfAc(certificado);
            }
            case APPFIRMAS_NAME -> {
                return CertificadoDataFactoryAppFirmas.getDatosUsuarioAppFirmas(certificado);
            }
            case AGOSDATA_NAME -> {
                return CertificadoDataFactoryArgosData.getDatosUsuarioArgosData(certificado);
            }
            case AGOSDATA_NAME_OLD -> {
                return CertificadoDataFactoryArgosData.getDatosUsuarioArgosData(certificado);
            }
            case BCE_NAME -> {
                return CertificadoDataFactoryBancoCentral.getDatosUsuarioBancoCentral(certificado);
            }
            case CJ_NAME -> {
                return CertificadoDataFactoryConsejoJudicatura.getDatosUsuarioConsejoJudicatura(certificado);
            }
            case CORPNEWBEST_NAME -> {
                return CertificadoDataFactoryCorpNewBest.getDatosUsuarioCorpNewBest(certificado);
            }
            case DARKCAM_NAME -> {
                return CertificadoDataFactoryDarkcam.getDatosUsuarioDarkcam(certificado);
            }
            case DATIL_NAME -> {
                return CertificadoDataFactoryDatil.getDatosUsuarioDatil(certificado);
            }
            case DIGERCIC_NAME -> {
                return CertificadoDataFactoryDatil.getDatosUsuarioDatil(certificado);
            }
            case ECLIPSOFT_NAME -> {
                return CertificadoDataFactoryEclipsoft.getDatosUsuarioEclipsoft(certificado);
            }
            case FIRMASEGURA_NAME -> {
                return CertificadoDataFactoryFirmaSegura.getDatosUsuarioFirmaSegura(certificado);
            }
            case LAZZATE_NAME -> {
                return CertificadoDataFactoryLazzate.getDatosUsuarioLazzate(certificado);
            }
            case LETMI_NAME -> {
                return CertificadoDataFactoryLetmi.getDatosUsuarioLetmi(certificado);
            }
            case PRIMECORELAT_NAME -> {
                return CertificadoDataFactoryPrimeCoreLat.getDatosUsuarioPrimeCoreLat(certificado);
            }
            case SECURITYDATA_NAME -> {
                return CertificadoDataFactorySecurityData.getDatosUsuarioSecurityData(certificado);
            }
            case SECURITYDATA_NAME_OLD -> {
                return CertificadoDataFactorySecurityData.getDatosUsuarioSecurityData(certificado);
            }
            case UANATACA_NAME -> {
                return CertificadoDataFactoryUanataca.getDatosUsuarioUanataca(certificado);
            }
            case UANATACA_NAME_OLD -> {
                return CertificadoDataFactoryUanataca.getDatosUsuarioUanataca(certificado);
            }
//            default ->
//                throw new EntidadCertificadoraNoValidaException("Entidad Certificadora no reconocida");
        }
        return null;
    }
}
