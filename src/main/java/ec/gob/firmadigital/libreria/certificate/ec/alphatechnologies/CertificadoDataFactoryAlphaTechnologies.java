/*
 * Copyright (C) 2026
 * Authors: Misael Fernández, ALPHA TECHNOLOGIES CIA. LTDA.
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
package ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies;

import ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies.ext.*;
import ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies.subj.*;
import ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.subj.CertificadoSubjImpl;
import static ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies.CertificadoAlphaTechnologies.*;
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
 * @author Misael Fernández, ALPHA TECHNOLOGIES CIA. LTDA.
 */
public class CertificadoDataFactoryAlphaTechnologies {

    public static X509Certificate getRootCertificate(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        try {
            if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertAlphaTechnologies20232026())) {
                System.out.println("AlphaTechnologiesSubCaCert 2023-2026");
                return new SubCaCertAlphaTechnologies20232026();
            }
            if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertAlphaTechnologies20242032())) {
                System.out.println("AlphaTechnologiesSubCaCert 2024-2032");
                return new SubCaCertAlphaTechnologies20242032();
            }
        } catch (java.security.InvalidKeyException ex) {
            throw new EntidadCertificadoraNoValidaException("Entidad Certificadora no reconocida");
        }
        return null;
    }

    public static DatosUsuario getDatosUsuarioAlphaTechnologies(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        DatosUsuario datosUsuario = null;
        if (esCertificadoDeAlphaTechnologies(certificado)) {
            datosUsuario = new DatosUsuario();
            Certificado certificadoAlphaTechnologies = construir(certificado);
            if (certificadoAlphaTechnologies instanceof CertificadoExtImplAlphaTechnologies) {
                if (certificadoAlphaTechnologies instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                            + certificadoPersonaNatural.getSegundoApellido());
                }
                if (certificadoAlphaTechnologies instanceof CertificadoMiembroEmpresa certificadoMiembroEmpresa) {
                    datosUsuario.setCedula(certificadoMiembroEmpresa.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoMiembroEmpresa.getNombres());
                    datosUsuario.setApellido(certificadoMiembroEmpresa.getPrimerApellido() + " "
                            + certificadoMiembroEmpresa.getSegundoApellido());
                    datosUsuario.setRuc(certificadoMiembroEmpresa.getRuc());
                    datosUsuario.setRazonSocial(certificadoMiembroEmpresa.getRazonSocial());
                    datosUsuario.setCargo(certificadoMiembroEmpresa.getCargo());
                }
                if (certificadoAlphaTechnologies instanceof CertificadoPersonaJuridica certificadoPersonaJuridica) {
                    datosUsuario.setCedula(certificadoPersonaJuridica.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaJuridica.getNombres());
                    datosUsuario.setApellido(certificadoPersonaJuridica.getPrimerApellido() + " "
                            + certificadoPersonaJuridica.getSegundoApellido());
                    datosUsuario.setRuc(certificadoPersonaJuridica.getRuc());
                    datosUsuario.setRazonSocial(certificadoPersonaJuridica.getRazonSocial());
                    datosUsuario.setCargo(certificadoPersonaJuridica.getCargo());
                }
            }
            //RESOLUCION-ARCOTEL-2024-0176
            if (certificadoAlphaTechnologies instanceof CertificadoSubjImpl) {
                if (certificadoAlphaTechnologies instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido());
                }
                if (certificadoAlphaTechnologies instanceof CertificadoMiembroEmpresa certificadoMiembroEmpresa) {
                    datosUsuario.setCedula(certificadoMiembroEmpresa.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoMiembroEmpresa.getNombres());
                    datosUsuario.setApellido(certificadoMiembroEmpresa.getPrimerApellido());
                    datosUsuario.setRuc(certificadoMiembroEmpresa.getRuc());
                    datosUsuario.setRazonSocial(certificadoMiembroEmpresa.getRazonSocial());
                    datosUsuario.setCargo(certificadoMiembroEmpresa.getCargo());
                }
                if (certificadoAlphaTechnologies instanceof CertificadoRepresentanteLegal certificadoRepresentanteLegal) {
                    datosUsuario.setCedula(certificadoRepresentanteLegal.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoRepresentanteLegal.getNombres());
                    datosUsuario.setApellido(certificadoRepresentanteLegal.getPrimerApellido());
                    datosUsuario.setRuc(certificadoRepresentanteLegal.getRuc());
                    datosUsuario.setRazonSocial(certificadoRepresentanteLegal.getRazonSocial());
                    datosUsuario.setCargo(certificadoRepresentanteLegal.getCargo());
                }
            }
            datosUsuario.setCertificadoDigitalValido(true);
        }
        return datosUsuario;
    }

    private static boolean esCertificadoDeAlphaTechnologies(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)
                //RESOLUCION-ARCOTEL-2024-0176
                || certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA)
                || certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL));
    }

    private static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoExtPersonaNaturalAlphaTechnologies(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA)) {
            return new CertificadoExtPersonaJuridicaAlphaTechnologies(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)) {
            return new CertificadoExtMiembroEmpresaAlphaTechnologies(certificado);
        } //RESOLUCION-ARCOTEL-2024-0176
        else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoSubjPersonaNaturalAlphaTechnologies(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA)) {
            return new CertificadoSubjMiembroEmpresaAlphaTechnologies(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL)) {
            return new CertificadoSubjRepresentanteLegalAlphaTechnologies(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de ALPHA TECHNOLOGIES CIA. LTDA. sin categorizar!");
        }
    }
}
