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

    public static DatosUsuario getDatosUsuarioUanataca(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        DatosUsuario datosUsuario = null;
        if (esCertificadoUanataca(certificado)) {
            datosUsuario = new DatosUsuario();
            Certificado certificadoUanataca = construir(certificado);
            if (certificadoUanataca instanceof CertificadoExtImplUanataca) {
                if (certificadoUanataca instanceof CertificadoExtPersonaNaturalUanataca certificadoPersonaNaturalU) {
                    datosUsuario.setCedula(certificadoPersonaNaturalU.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNaturalU.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNaturalU.getPrimerApellido() + " "
                            + certificadoPersonaNaturalU.getSegundoApellido());
                }
                if (certificadoUanataca instanceof CertificadoExtMiembroEmpresaUanataca certificadoMiembroEmpresaUanataca) {
                    datosUsuario.setCedula(certificadoMiembroEmpresaUanataca.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoMiembroEmpresaUanataca.getNombres());
                    datosUsuario.setApellido(certificadoMiembroEmpresaUanataca.getPrimerApellido() + " "
                            + certificadoMiembroEmpresaUanataca.getSegundoApellido());
                    datosUsuario.setCargo(certificadoMiembroEmpresaUanataca.getCargo());
                }
                if (certificadoUanataca instanceof CertificadoExtPersonaJuridicaPrivadaUanataca certificadoPersonaJuridicaUanataca) {
                    datosUsuario.setCedula(certificadoPersonaJuridicaUanataca.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaJuridicaUanataca.getNombres());
                    datosUsuario.setApellido(certificadoPersonaJuridicaUanataca.getPrimerApellido() + " "
                            + certificadoPersonaJuridicaUanataca.getSegundoApellido());
                    datosUsuario.setCargo(datosUsuario.getCargo());
                }
                if (certificadoUanataca instanceof CertificadoExtRepresentanteLegalUanataca certificadoRepresentanteLegalUanataca) {
                    datosUsuario.setCedula(certificadoRepresentanteLegalUanataca.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoRepresentanteLegalUanataca.getNombres());
                    datosUsuario.setApellido(certificadoRepresentanteLegalUanataca.getPrimerApellido() + " "
                            + certificadoRepresentanteLegalUanataca.getSegundoApellido());
                    datosUsuario.setCargo(certificadoRepresentanteLegalUanataca.getCargo());
                }
                if (certificadoUanataca instanceof CertificadoSelladoTiempo certificadoSelladoTiempo) {
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

    private static boolean esCertificadoUanataca(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_EMPRESA)
                || certificateHasPolicy(certificado, Ext.OID_SELLADO_TIEMPO)
                //RESOLUCION-ARCOTEL-2024-0176
//                || certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)
                );
    }

    private static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
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
//        }
        //RESOLUCION-ARCOTEL-2024-0176
//        else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
//            return new CertificadoSubjPersonaNaturalAlphaTechnologies(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de UANATACA ECUADOR S.A. sin categorizar!");
        }
    }

}
