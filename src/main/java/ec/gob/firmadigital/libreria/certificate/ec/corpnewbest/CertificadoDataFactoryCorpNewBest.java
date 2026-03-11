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
package ec.gob.firmadigital.libreria.certificate.ec.corpnewbest;

import ec.gob.firmadigital.libreria.certificate.ec.corpnewbest.ext.*;
//import ec.gob.firmadigital.libreria.certificate.ec.corpnewbest.subj.*;
import ec.gob.firmadigital.libreria.certificate.ec.corpnewbest.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.subj.CertificadoSubjImpl;
import static ec.gob.firmadigital.libreria.certificate.ec.corpnewbest.CertificadoCorpNewBest.*;
import ec.gob.firmadigital.libreria.certificate.ec.*;
import ec.gob.firmadigital.libreria.certificate.Certificado;
import ec.gob.firmadigital.libreria.certificate.to.DatosUsuario;
import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import java.security.cert.X509Certificate;
import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy;

/**
 * Permite construir certificados tipo Certificado de la entidad de
 * certificación a partir de certificados X509Certificate.
 *
 * @author Misael Fernández, CORPNEWBEST CIA. LTDA.
 */
public class CertificadoDataFactoryCorpNewBest {

    public static X509Certificate getRootCertificate(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
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
        } catch (java.security.InvalidKeyException ex) {
            throw new EntidadCertificadoraNoValidaException("Entidad Certificadora no reconocida");
        }
        return null;
    }

    public static DatosUsuario getDatosUsuarioCorpNewBest(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        DatosUsuario datosUsuario = null;
        if (esCertificadoCorpNewBest(certificado)) {
            datosUsuario = new DatosUsuario();
            Certificado certificadoCorpNewBest = construir(certificado);
            if (certificadoCorpNewBest instanceof CertificadoExtImplCorpNewBest) {
                if (certificadoCorpNewBest instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                            + certificadoPersonaNatural.getSegundoApellido());
                }
                if (certificadoCorpNewBest instanceof CertificadoPersonaJuridica certificadoPersonaJuridica) {
                    datosUsuario.setCedula(certificadoPersonaJuridica.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaJuridica.getNombres());
                    datosUsuario.setApellido(certificadoPersonaJuridica.getPrimerApellido() + " "
                            + certificadoPersonaJuridica.getSegundoApellido());
                    datosUsuario.setRuc(certificadoPersonaJuridica.getRuc());
                    datosUsuario.setRazonSocial(certificadoPersonaJuridica.getRazonSocial());
                    datosUsuario.setCargo(certificadoPersonaJuridica.getCargo());
                }
                if (certificadoCorpNewBest instanceof CertificadoMiembroEmpresa certificadoMiembroEmpresa) {
                    datosUsuario.setCedula(certificadoMiembroEmpresa.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoMiembroEmpresa.getNombres());
                    datosUsuario.setApellido(certificadoMiembroEmpresa.getPrimerApellido() + " "
                            + certificadoMiembroEmpresa.getSegundoApellido());
                    datosUsuario.setRuc(certificadoMiembroEmpresa.getRuc());
                    datosUsuario.setRazonSocial(certificadoMiembroEmpresa.getRazonSocial());
                    datosUsuario.setCargo(certificadoMiembroEmpresa.getCargo());
                }
                if (certificadoCorpNewBest instanceof CertificadoSelladoTiempo) {
                    datosUsuario.setCertificadoDigitalValido(true);
                }
            }
            //RESOLUCION-ARCOTEL-2024-0176
//            if (certificadoAlphaTechnologies instanceof CertificadoSubjImpl) {
//                if (certificadoAlphaTechnologies instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
//                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
//                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
//                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido());
//                }
//            }
            datosUsuario.setCertificadoDigitalValido(true);
        }
        return datosUsuario;
    }

    private static boolean esCertificadoCorpNewBest(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)
                //RESOLUCION-ARCOTEL-2024-0176
//                || certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)
                );
    }

    private static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoExtPersonaNaturalCorpNewBest(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA)) {
            return new CertificadoExtPersonaJuridicaCorpNewBest(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)) {
            return new CertificadoExtMiembroEmpresaCorpNewBest(certificado);
//        }
            //RESOLUCION-ARCOTEL-2024-0176
//        else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
//            return new CertificadoSubjPersonaNaturalAlphaTechnologies(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Tipo Certificado de CORPNEWBEST CIA. LTDA. sin categorizar!");
        }
    }
}
