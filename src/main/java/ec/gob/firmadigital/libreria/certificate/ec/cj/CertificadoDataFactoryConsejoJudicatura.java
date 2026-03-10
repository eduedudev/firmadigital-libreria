/*
 * Copyright (C) 2026 
 * Authors: Misael Fernández, CONSEJO DE LA JUDICATURA
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
package ec.gob.firmadigital.libreria.certificate.ec.cj;

import ec.gob.firmadigital.libreria.certificate.ec.cj.ext.*;
//import ec.gob.firmadigital.libreria.certificate.ec.cj.subj.*;
import static ec.gob.firmadigital.libreria.certificate.ec.cj.CertificadoConsejoJudicatura.*;
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
 * @author Misael Fernández, CONSEJO DE LA JUDICATURA
 */
public class CertificadoDataFactoryConsejoJudicatura {

    public static DatosUsuario getDatosUsuarioConsejoJudicatura(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        DatosUsuario datosUsuario = null;
        if (esCertificadoDelConsejoJudicatura(certificado)) {
            datosUsuario = new DatosUsuario();
            Certificado certificadoConsejoJudicatura = construir(certificado);
            if (certificadoConsejoJudicatura instanceof CertificadoExtImplConsejoJudicatura) {
                if (certificadoConsejoJudicatura instanceof CertificadoExtPersonaNaturalConsejoJudicatura certificadoPersonaNaturalConsejoJudicatura) {
                    datosUsuario.setCedula(certificadoPersonaNaturalConsejoJudicatura.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNaturalConsejoJudicatura.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNaturalConsejoJudicatura.getPrimerApellido() + " "
                            + certificadoPersonaNaturalConsejoJudicatura.getSegundoApellido());
                }
                if (certificadoConsejoJudicatura instanceof CertificadoExtDepartamentoEmpresaConsejoJudicatura certificadoDepartamentoEmpresaConsejoJudicatura) {
                    datosUsuario.setCedula(certificadoDepartamentoEmpresaConsejoJudicatura.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoDepartamentoEmpresaConsejoJudicatura.getNombres());
                    datosUsuario.setApellido(certificadoDepartamentoEmpresaConsejoJudicatura.getPrimerApellido() + " "
                            + certificadoDepartamentoEmpresaConsejoJudicatura.getSegundoApellido());
                    datosUsuario.setRuc(certificadoDepartamentoEmpresaConsejoJudicatura.getRuc());
                    datosUsuario.setRazonSocial(certificadoDepartamentoEmpresaConsejoJudicatura.getRazonSocial());
                    datosUsuario.setCargo(certificadoDepartamentoEmpresaConsejoJudicatura.getCargo());
                }
                if (certificadoConsejoJudicatura instanceof CertificadoExtEmpresaConsejoJudicatura certificadoEmpresaConsejoJudicatura) {
                    datosUsuario.setCedula(certificadoEmpresaConsejoJudicatura.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoEmpresaConsejoJudicatura.getNombres());
                    datosUsuario.setApellido(certificadoEmpresaConsejoJudicatura.getPrimerApellido() + " "
                            + certificadoEmpresaConsejoJudicatura.getSegundoApellido());
                    datosUsuario.setRuc(certificadoEmpresaConsejoJudicatura.getRuc());
                    datosUsuario.setRazonSocial(certificadoEmpresaConsejoJudicatura.getRazonSocial());
                    datosUsuario.setCargo(certificadoEmpresaConsejoJudicatura.getCargo());
                }
                if (certificadoConsejoJudicatura instanceof CertificadoExtMiembroEmpresaConsejoJudicatura certificadoMiembroEmpresaConsejoJudicatura) {
                    datosUsuario.setCedula(certificadoMiembroEmpresaConsejoJudicatura.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoMiembroEmpresaConsejoJudicatura.getNombres());
                    datosUsuario.setApellido(certificadoMiembroEmpresaConsejoJudicatura.getPrimerApellido() + " "
                            + certificadoMiembroEmpresaConsejoJudicatura.getSegundoApellido());
                    datosUsuario.setRuc(certificadoMiembroEmpresaConsejoJudicatura.getRuc());
                    datosUsuario.setRazonSocial(certificadoMiembroEmpresaConsejoJudicatura.getRazonSocial());
                    datosUsuario.setCargo(certificadoMiembroEmpresaConsejoJudicatura.getCargo());
                }
                if (certificadoConsejoJudicatura instanceof CertificadoExtPersonaJuridicaPrivadaConsejoJudicatura certificadoPersonaJuridicaPrivadaConsejoJudicatura) {
                    datosUsuario.setCedula(certificadoPersonaJuridicaPrivadaConsejoJudicatura.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaJuridicaPrivadaConsejoJudicatura.getNombres());
                    datosUsuario.setApellido(certificadoPersonaJuridicaPrivadaConsejoJudicatura.getPrimerApellido() + " "
                            + certificadoPersonaJuridicaPrivadaConsejoJudicatura.getSegundoApellido());
                    datosUsuario.setRuc(datosUsuario.getRuc());
                    datosUsuario.setRazonSocial(datosUsuario.getRazonSocial());
                    datosUsuario.setCargo(datosUsuario.getCargo());
                }
                if (certificadoConsejoJudicatura instanceof CertificadoExtPersonaJuridicaPublicaConsejoJudicatura certificadoPersonaJuridicaPublicaConsejoJudicatura) {
                    datosUsuario.setCedula(certificadoPersonaJuridicaPublicaConsejoJudicatura.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaJuridicaPublicaConsejoJudicatura.getNombres());
                    datosUsuario.setApellido(certificadoPersonaJuridicaPublicaConsejoJudicatura.getPrimerApellido() + " "
                            + certificadoPersonaJuridicaPublicaConsejoJudicatura.getSegundoApellido());
                    datosUsuario.setRuc(certificadoPersonaJuridicaPublicaConsejoJudicatura.getRuc());
                    datosUsuario.setRazonSocial(certificadoPersonaJuridicaPublicaConsejoJudicatura.getRazonSocial());
                    datosUsuario.setCargo(certificadoPersonaJuridicaPublicaConsejoJudicatura.getCargo());
                }
                if (certificadoConsejoJudicatura instanceof CertificadoSelladoTiempo certificadoSelladoTiempo) {
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

    private static boolean esCertificadoDelConsejoJudicatura(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_PRIVADA)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_PUBLICA)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_EMPRESA)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_DEPARTAMENTO_EMPRESA)
                || certificateHasPolicy(certificado, Ext.OID_SELLADO_TIEMPO)
                //RESOLUCION-ARCOTEL-2024-0176
//                || certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)
                );
    }

    private static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoExtPersonaNaturalConsejoJudicatura(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_PRIVADA)) {
            return new CertificadoExtPersonaJuridicaPrivadaConsejoJudicatura(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_PUBLICA)) {
            return new CertificadoExtPersonaJuridicaPublicaConsejoJudicatura(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)) {
            return new CertificadoExtMiembroEmpresaConsejoJudicatura(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_EMPRESA)) {
            return new CertificadoExtEmpresaConsejoJudicatura(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_DEPARTAMENTO_EMPRESA)) {
            return new CertificadoExtDepartamentoEmpresaConsejoJudicatura(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_SELLADO_TIEMPO)) {
            return new CertificadoExtSelladoTiempoConsejoJudicatura(certificado);
//        }
        //RESOLUCION-ARCOTEL-2024-0176
//        else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
//            return new CertificadoSubjPersonaNaturalAlphaTechnologies(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado del CONSEJO DE LA JUDICATURA sin categorizar!");
        }
    }
}
