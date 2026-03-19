/*
 * Copyright (C) 2026
 * Authors: Misael Fernández, ARGOSDATA CERTIFICACIÓN DE INFORMACIÓN Y SERVICIOS RELACIONADOS S.A.S.
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
package ec.gob.firmadigital.libreria.certificate.ec.argosdata;

import ec.gob.firmadigital.libreria.certificate.ec.argosdata.ext.*;
import ec.gob.firmadigital.libreria.certificate.ec.argosdata.subj.*;
import ec.gob.firmadigital.libreria.certificate.ec.argosdata.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.subj.CertificadoSubjImpl;
import static ec.gob.firmadigital.libreria.certificate.ec.argosdata.CertificadoArgosData.*;
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
 * @author Misael Fernández, ARGOSDATA CERTIFICACIÓN DE INFORMACIÓN Y SERVICIOS
 * RELACIONADOS S.A.S.
 */
public class CertificadoDataFactoryArgosData {

    public static X509Certificate getRootCertificate(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        try {
            if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertArgosData())) {
                System.out.println("SubCA ArgosData");
                return new SubCaCertArgosData();
            }
        } catch (java.security.InvalidKeyException ex) {
            throw new EntidadCertificadoraNoValidaException("Entidad Certificadora no reconocida");
        }
        return null;
    }

    public static DatosUsuario getDatosUsuarioArgosData(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        DatosUsuario datosUsuario = null;
        if (esCertificadoArgosData(certificado)) {
            datosUsuario = new DatosUsuario();
            Certificado certificadoArgosData = construir(certificado);
            if (certificadoArgosData instanceof CertificadoExtImplArgosData) {
                if (certificadoArgosData instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                            + certificadoPersonaNatural.getSegundoApellido());
                }
                if (certificadoArgosData instanceof CertificadoRepresentanteLegal certificadoRepresentanteLegal) {
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
            if (certificadoArgosData instanceof CertificadoSubjImpl) {
                if (certificadoArgosData instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido());
                }
            }
            if (certificadoArgosData instanceof CertificadoSubjImpl) {
                if (certificadoArgosData instanceof CertificadoRepresentanteLegal certificadoRepresentanteLegal) {
                    datosUsuario.setCedula(certificadoRepresentanteLegal.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoRepresentanteLegal.getNombres());
                    datosUsuario.setApellido(certificadoRepresentanteLegal.getPrimerApellido());
                    datosUsuario.setRuc(certificadoRepresentanteLegal.getRuc());
                    datosUsuario.setRazonSocial(certificadoRepresentanteLegal.getRazonSocial());
                }
            }
            datosUsuario.setCertificadoDigitalValido(true);
        }
        return datosUsuario;
    }

    private static boolean esCertificadoArgosData(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_LEGAL)
                //RESOLUCION-ARCOTEL-2024-0176
                || certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL));
    }

    private static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoExtPersonaNaturalArgosData(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_LEGAL)) {
            return new CertificadoExtRepresentanteLegalArgosData(certificado);
        } //RESOLUCION-ARCOTEL-2024-0176
        else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoSubjPersonaNaturalArgosData(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL)) {
            return new CertificadoSubjRepresentanteLegalArgosData(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de ARGOSDATA CERTIFICACIÓN DE INFORMACIÓN Y SERVICIOS RELACIONADOS S.A.S. sin categorizar!");
        }
    }
}
