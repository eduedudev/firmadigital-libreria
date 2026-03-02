/*
 * Copyright (C) 2026
 * Authors: Misael Fernández, FIRMASEGURA S.A.S.
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
package ec.gob.firmadigital.libreria.certificate.ec.firmasegura;

import ec.gob.firmadigital.libreria.certificate.ec.firmasegura.ext.*;
//import ec.gob.firmadigital.libreria.certificate.ec.firmasegura.subj.*;
import static ec.gob.firmadigital.libreria.certificate.ec.firmasegura.CertificadoFirmaSegura.*;
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
 * @author Misael Fernández, FIRMASEGURA S.A.S.
 */
public class CertificadoDataFactoryFirmaSegura {

    public static DatosUsuario getDatosUsuarioFirmaSegura(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        DatosUsuario datosUsuario = null;
        if (esCertificadoDeFirmaSegura(certificado)) {
            datosUsuario = new DatosUsuario();
            Certificado certificadoFirmaSegura = construir(certificado);
            if (certificadoFirmaSegura instanceof CertificadoExtImplFirmaSegura) {
                if (certificadoFirmaSegura instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                            + certificadoPersonaNatural.getSegundoApellido());
                }
                if (certificadoFirmaSegura instanceof CertificadoRepresentanteLegal certificadoRepresentanteLegal) {
                    datosUsuario.setCedula(certificadoRepresentanteLegal.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoRepresentanteLegal.getNombres());
                    datosUsuario.setApellido(certificadoRepresentanteLegal.getPrimerApellido() + " "
                            + certificadoRepresentanteLegal.getSegundoApellido());
                    datosUsuario.setRuc(certificadoRepresentanteLegal.getRuc());
                    datosUsuario.setRazonSocial(certificadoRepresentanteLegal.getRazonSocial());
                    datosUsuario.setCargo(certificadoRepresentanteLegal.getCargo());
                }
            }
            //RESOLUCION-ARCOTEL-2024-0176
//            if (certificadoAlphaTechnologies instanceof CertificadoSubjImplAlphaTechnologies) {
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

    private static boolean esCertificadoDeFirmaSegura(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_LEGAL)
                //RESOLUCION-ARCOTEL-2024-0176
//                || certificateHasPolicy2(certificado, Subj.OID_TIPO_PERSONA_NATURAL)
                );
    }

    private static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoExtPersonaNaturalFirmaSegura(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_LEGAL)) {
            return new CertificadoExtRepresentanteLegalFirmaSegura(certificado);
//        }
        //RESOLUCION-ARCOTEL-2024-0176
//        else if (certificateHasPolicy2(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
//            return new CertificadoSubjPersonaNaturalAlphaTechnologies(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Tipo Certificado de FIRMASEGURA S.A.S. sin categorizar!");
        }
    }
}
