/*
 * Copyright (C) 2026 
 * Authors: Misael Fernández, DIRECCIÓN GENERAL DE REGISTRO CIVIL, IDENTIFICACIÓN Y CEDULACIÓN
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
package ec.gob.firmadigital.libreria.certificate.ec.digercic;

import ec.gob.firmadigital.libreria.certificate.ec.digercic.ext.*;
//import ec.gob.firmadigital.libreria.certificate.ec.digercic.subj.*;
import static ec.gob.firmadigital.libreria.certificate.ec.digercic.CertificadoDigercic.*;
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
 * @author Misael Fernández, DIRECCIÓN GENERAL DE REGISTRO CIVIL, IDENTIFICACIÓN
 * Y CEDULACIÓN
 */
public class CertificadoDataFactoryDigercic {

    public static DatosUsuario getDatosUsuarioDatil(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        DatosUsuario datosUsuario = null;
        if (CertificadoDataFactoryDigercic.esCertificadoDigercic(certificado)) {
            datosUsuario = new DatosUsuario();
            Certificado certificadoDigercic = construir(certificado);
            if (certificadoDigercic instanceof CertificadoExtImplDigercic) {
                if (certificadoDigercic instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(ec.gob.firmadigital.libreria.utils.Utils.getCN(certificado));
                    datosUsuario.setApellido("");
                }
            }
//        }
        //RESOLUCION-ARCOTEL-2024-0176
//        else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
//            return new CertificadoSubjPersonaNaturalAlphaTechnologies(certificado);
            datosUsuario.setCertificadoDigitalValido(true);
        }
        return datosUsuario;
    }

    private static boolean esCertificadoDigercic(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)
                //RESOLUCION-ARCOTEL-2024-0176
//                || certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)
                );
    }

    private static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoExtPersonaNaturalDigercic(certificado);
//        }
        //RESOLUCION-ARCOTEL-2024-0176
//        else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
//            return new CertificadoSubjPersonaNaturalAlphaTechnologies(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de DIRECCIÓN GENERAL DE REGISTRO CIVIL, IDENTIFICACIÓN sin categorizar!");
        }
    }
}
