/*
 * Copyright (C) 2026 
 * Authors: Misael Fernández, ECLIPSOFT S.A.
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
package ec.gob.firmadigital.libreria.certificate.ec.eclipsoft;

import ec.gob.firmadigital.libreria.certificate.ec.eclipsoft.ext.*;
//import ec.gob.firmadigital.libreria.certificate.ec.eclipsoft.subj.*;
//import ec.gob.firmadigital.libreria.certificate.ec.eclipsoft.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.subj.CertificadoSubjImpl;
import static ec.gob.firmadigital.libreria.certificate.ec.eclipsoft.CertificadoEclipsoft.*;
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
 * @author Misael Fernández, ECLIPSOFT S.A.
 */
public class CertificadoDataFactoryEclipsoft {

//    public static X509Certificate getRootCertificate(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
//        try {
//            if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertAlphaTechnologies20232026())) {
//                System.out.println("AlphaTechnologiesSubCaCert 2023-2026");
//                return new SubCaCertAlphaTechnologies20232026();
//            }
//        } catch (java.security.InvalidKeyException ex) {
//            throw new EntidadCertificadoraNoValidaException("Entidad Certificadora no reconocida");
//        }
//        return null;
//    }
    
    public static DatosUsuario getDatosUsuarioEclipsoft(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        DatosUsuario datosUsuario = null;
        Certificado certificadoEclipsoft = construir(certificado);
        if (certificadoEclipsoft != null) {
            datosUsuario = new DatosUsuario();
            if (certificadoEclipsoft instanceof CertificadoExtImplEcplipsoft) {
                if (certificadoEclipsoft instanceof CertificadoPersonaNatural certificadoPersonaNaturalEclipsoft) {
                    datosUsuario.setCedula(certificadoPersonaNaturalEclipsoft.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNaturalEclipsoft.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNaturalEclipsoft.getPrimerApellido() + " "
                            + certificadoPersonaNaturalEclipsoft.getSegundoApellido());
                }
                if (certificadoEclipsoft instanceof CertificadoMiembroEmpresa certificadoMiembroEmpresaEclipsoft) {
                    datosUsuario.setCedula(certificadoMiembroEmpresaEclipsoft.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoMiembroEmpresaEclipsoft.getNombres());
                    datosUsuario.setApellido(certificadoMiembroEmpresaEclipsoft.getPrimerApellido() + " "
                            + certificadoMiembroEmpresaEclipsoft.getSegundoApellido());
                    datosUsuario.setRuc(certificadoMiembroEmpresaEclipsoft.getRuc());
                    datosUsuario.setRazonSocial(certificadoMiembroEmpresaEclipsoft.getRazonSocial());
                    datosUsuario.setCargo(certificadoMiembroEmpresaEclipsoft.getCargo());
                }
                if (certificadoEclipsoft instanceof CertificadoRepresentanteLegal certificadoRepresentanteLegalEclipsoft) {
                    datosUsuario.setCedula(certificadoRepresentanteLegalEclipsoft.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoRepresentanteLegalEclipsoft.getNombres());
                    datosUsuario.setApellido(certificadoRepresentanteLegalEclipsoft.getPrimerApellido() + " "
                            + certificadoRepresentanteLegalEclipsoft.getSegundoApellido());
                    datosUsuario.setRuc(certificadoRepresentanteLegalEclipsoft.getRuc());
                    datosUsuario.setRazonSocial(certificadoRepresentanteLegalEclipsoft.getRazonSocial());
                    datosUsuario.setCargo(certificadoRepresentanteLegalEclipsoft.getCargo());
                }
                if (certificadoEclipsoft instanceof CertificadoPersonaJuridica certificadoPersonaJuridicaPrivadaEclipsoft) {
                    datosUsuario.setCedula(certificadoPersonaJuridicaPrivadaEclipsoft.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaJuridicaPrivadaEclipsoft.getNombres());
                    datosUsuario.setApellido(certificadoPersonaJuridicaPrivadaEclipsoft.getPrimerApellido() + " "
                            + certificadoPersonaJuridicaPrivadaEclipsoft.getSegundoApellido());
                    datosUsuario.setRuc(datosUsuario.getRuc());
                    datosUsuario.setRazonSocial(datosUsuario.getRazonSocial());
                    datosUsuario.setCargo(datosUsuario.getCargo());
                }
                if (certificadoEclipsoft instanceof CertificadoSelladoTiempo certificadoSelladoTiempo) {
                    datosUsuario.setCommonName(certificadoSelladoTiempo.getCommonName());
                    datosUsuario.setRuc(certificadoSelladoTiempo.getRuc());
                    datosUsuario.setRazonSocial(certificadoSelladoTiempo.getRazonSocial());
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

    private static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (ec.gob.firmadigital.libreria.certificate.CertUtils.hasExtensionMatchingPattern(certificado, "1.3.6.1.4.1", "3.1")) {
            if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
                return new CertificadoExtPersonalNaturalEclipsoft(certificado);
            } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)) {
                return new CertificadoExtMiembroEmpresaEclipsoft(certificado);
            } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_EMPRESA)) {
                return new CertificadoExtRepresentanteLegalEclipsoft(certificado);
            } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA)) {
                return new CertificadoExtPersonaJuridicaPrivadaEclipsoft(certificado);
            } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_SELLADO_TIEMPO)) {
                return new CertificadoExtSelladoTiempoEclipsoft(certificado);
            } else {
                throw new EntidadCertificadoraNoValidaException("Certificado del ECLIPSOFT S.A. sin categorizar!");
            }
//        } else {//RESOLUCION-ARCOTEL-2024-0176
//            if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
//                return new CertificadoSubjPersonaNaturalAlphaTechnologies(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado del ECLIPSOFT S.A. sin categorizar!");
        }
    }
}
