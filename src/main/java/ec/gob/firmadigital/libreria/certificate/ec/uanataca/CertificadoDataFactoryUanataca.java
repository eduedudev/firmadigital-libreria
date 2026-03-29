/*
 * Copyright (C) 2026 
 * Authors: Misael Fernández, UANATACA ECUADOR S.A.
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
package ec.gob.firmadigital.libreria.certificate.ec.uanataca;

import ec.gob.firmadigital.libreria.certificate.ec.uanataca.ext.*;
//import ec.gob.firmadigital.libreria.certificate.ec.uanataca.subj.*;
import ec.gob.firmadigital.libreria.certificate.ec.uanataca.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.subj.CertificadoSubjImpl;
import static ec.gob.firmadigital.libreria.certificate.ec.uanataca.CertificadoUanataca.*;
import ec.gob.firmadigital.libreria.certificate.ec.*;
import ec.gob.firmadigital.libreria.certificate.Certificado;
import ec.gob.firmadigital.libreria.certificate.ec.uanataca.ext.CertificadoExtImplUanataca;
import ec.gob.firmadigital.libreria.certificate.to.DatosUsuario;
import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import java.security.cert.X509Certificate;
import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy;

/**
 * Permite construir certificados tipo Certificado de la entidad de
 * certificación a partir de certificados X509Certificate.
 *
 * @author Misael Fernández, UANATACA ECUADOR S.A.
 */
public class CertificadoDataFactoryUanataca {

    public static X509Certificate getRootCertificate(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
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
        } catch (java.security.InvalidKeyException ex) {
            throw new EntidadCertificadoraNoValidaException("Entidad Certificadora no reconocida");
        }
        return null;
    }

    public static DatosUsuario getDatosUsuarioUanataca(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        DatosUsuario datosUsuario = null;
        Certificado certificadoUanataca = construir(certificado);
        if (certificadoUanataca != null) {
            datosUsuario = new DatosUsuario();
            if (certificadoUanataca instanceof CertificadoExtImplUanataca) {
                if (certificadoUanataca instanceof CertificadoExtPersonaNaturalUanataca certificadoPersonaNaturalU) {
                    datosUsuario.setTipoCertificado("Persona Natural (EXT)");
                    datosUsuario.setCedula(certificadoPersonaNaturalU.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNaturalU.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNaturalU.getPrimerApellido() + " "
                            + certificadoPersonaNaturalU.getSegundoApellido());
                }
                if (certificadoUanataca instanceof CertificadoExtMiembroEmpresaUanataca certificadoMiembroEmpresaUanataca) {
                    datosUsuario.setTipoCertificado("Miembro Empresa (EXT)");
                    datosUsuario.setCedula(certificadoMiembroEmpresaUanataca.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoMiembroEmpresaUanataca.getNombres());
                    datosUsuario.setApellido(certificadoMiembroEmpresaUanataca.getPrimerApellido() + " "
                            + certificadoMiembroEmpresaUanataca.getSegundoApellido());
                    datosUsuario.setCargo(certificadoMiembroEmpresaUanataca.getCargo());
                }
                if (certificadoUanataca instanceof CertificadoExtPersonaJuridicaPrivadaUanataca certificadoPersonaJuridicaUanataca) {
                    datosUsuario.setTipoCertificado("Persona Jurídica Privada (EXT)");
                    datosUsuario.setCedula(certificadoPersonaJuridicaUanataca.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaJuridicaUanataca.getNombres());
                    datosUsuario.setApellido(certificadoPersonaJuridicaUanataca.getPrimerApellido() + " "
                            + certificadoPersonaJuridicaUanataca.getSegundoApellido());
                    datosUsuario.setCargo(datosUsuario.getCargo());
                }
                if (certificadoUanataca instanceof CertificadoExtRepresentanteLegalUanataca certificadoRepresentanteLegalUanataca) {
                    datosUsuario.setTipoCertificado("Representante Legal (EXT)");
                    datosUsuario.setCedula(certificadoRepresentanteLegalUanataca.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoRepresentanteLegalUanataca.getNombres());
                    datosUsuario.setApellido(certificadoRepresentanteLegalUanataca.getPrimerApellido() + " "
                            + certificadoRepresentanteLegalUanataca.getSegundoApellido());
                    datosUsuario.setCargo(certificadoRepresentanteLegalUanataca.getCargo());
                }
                if (certificadoUanataca instanceof CertificadoExtSelladoTiempoUanataca certificadoSelladoTiempoUanataca) {
                    datosUsuario.setTipoCertificado("Sellado de Tiempo (EXT)");
                    datosUsuario.setCommonName(certificadoSelladoTiempoUanataca.getCommonName());
                    datosUsuario.setRuc(certificadoSelladoTiempoUanataca.getRuc());
                    datosUsuario.setRazonSocial(certificadoSelladoTiempoUanataca.getRazonSocial());
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

    private static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        ec.gob.firmadigital.libreria.utils.CertificateUtils.getExtensionsWithBouncyCastle(certificado);
        if (ec.gob.firmadigital.libreria.certificate.CertUtils.hasExtensionMatchingPattern(certificado, "1.3.6.1.4.1", "102.3.1")) {
            if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
                return new CertificadoExtPersonaNaturalUanataca(certificado);
            } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA)) {
                return new CertificadoExtPersonaJuridicaPrivadaUanataca(certificado);
            } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)) {
                return new CertificadoExtMiembroEmpresaUanataca(certificado);
            } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_EMPRESA)) {
                return new CertificadoExtRepresentanteLegalUanataca(certificado);
            } else if (certificateHasPolicy(certificado, Ext.OID_SELLADO_TIEMPO)) {
                return new CertificadoExtSelladoTiempoUanataca(certificado);
            } else {
                throw new EntidadCertificadoraNoValidaException("Certificado de UANATACA ECUADOR S.A. sin categorizar!");
            }
//        } else {//RESOLUCION-ARCOTEL-2024-0176
//            if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
//                return new CertificadoSubjPersonaNaturalAlphaTechnologies(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de UANATACA ECUADOR S.A. sin categorizar!");
        }
    }
}
