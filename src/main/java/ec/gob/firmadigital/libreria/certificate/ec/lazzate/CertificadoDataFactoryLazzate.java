/*
 * Copyright (C) 2026
 * Authors: Misael Fernández, LAZZATE CIA. LTDA.
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
package ec.gob.firmadigital.libreria.certificate.ec.lazzate;

import ec.gob.firmadigital.libreria.certificate.ec.lazzate.ext.*;
//import ec.gob.firmadigital.libreria.certificate.ec.lazzate.subj.*;
import static ec.gob.firmadigital.libreria.certificate.ec.lazzate.CertificadoLazzate.*;
import ec.gob.firmadigital.libreria.certificate.ec.*;
import ec.gob.firmadigital.libreria.certificate.Certificado;
import ec.gob.firmadigital.libreria.certificate.to.DatosUsuario;
import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import java.security.cert.X509Certificate;
import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy;

/**
 * Permite construir certificados tipo CertificadoLazzate a partir de
 * certificados X509Certificate.
 *
 * @author Misael Fernández, LAZZATE CIA. LTDA.
 */
public class CertificadoDataFactoryLazzate {

    public static DatosUsuario getDatosUsuarioLazzate(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        DatosUsuario datosUsuario = null;
        if (esCertificadoLazzate(certificado)) {
            datosUsuario = new DatosUsuario();
            Certificado certificadoLazzate = construir(certificado);
            if (certificadoLazzate instanceof CertificadoExtImplLazzate) {
                if (certificadoLazzate instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                            + certificadoPersonaNatural.getSegundoApellido());
                }
                if (certificadoLazzate instanceof CertificadoPersonaJuridica certificadoExtPersonaJuridicaLazzate) {
                    datosUsuario.setCedula(certificadoExtPersonaJuridicaLazzate.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoExtPersonaJuridicaLazzate.getNombres());
                    datosUsuario.setApellido(certificadoExtPersonaJuridicaLazzate.getPrimerApellido() + " "
                            + certificadoExtPersonaJuridicaLazzate.getSegundoApellido());
                    datosUsuario.setRuc(certificadoExtPersonaJuridicaLazzate.getRuc());
                    datosUsuario.setRazonSocial(certificadoExtPersonaJuridicaLazzate.getRazonSocial());
                    datosUsuario.setCargo(certificadoExtPersonaJuridicaLazzate.getCargo());
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

    private static boolean esCertificadoLazzate(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_EMPRESA)
                //RESOLUCION-ARCOTEL-2024-0176
//                || certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)
                );
    }

    private static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoExtPersonaNaturalLazzate(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_EMPRESA)) {
            return new CertificadoExtPersonaJuridicaLazzate(certificado);
//        }
        //RESOLUCION-ARCOTEL-2024-0176
//        else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
//            return new CertificadoSubjPersonaNaturalAlphaTechnologies(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de LAZZATE CIA. LTDA. sin categorizar!");
        }
    }
}
