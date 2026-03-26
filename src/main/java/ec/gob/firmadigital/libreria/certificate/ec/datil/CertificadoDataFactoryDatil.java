/*
 * Copyright (C) 2026 
 * Authors: Misael Fernández, DATILMEDIA S.A.
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
package ec.gob.firmadigital.libreria.certificate.ec.datil;

import ec.gob.firmadigital.libreria.certificate.ec.datil.ext.*;
import ec.gob.firmadigital.libreria.certificate.ec.datil.subj.*;
import ec.gob.firmadigital.libreria.certificate.ec.datil.cert.*;
import ec.gob.firmadigital.libreria.certificate.ec.subj.CertificadoSubjImpl;
import static ec.gob.firmadigital.libreria.certificate.ec.datil.CertificadoDatil.*;
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
 * @author Misael Fernández, DATILMEDIA S.A.
 */
public class CertificadoDataFactoryDatil {

    public static X509Certificate getRootCertificate(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        try {
            if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertDatil20212031())) {
                System.out.println("SubCA DatilMedia 2021-2031");
                return new SubCaCertDatil20212031();
            }
            if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertDatil20252035())) {
                System.out.println("SubCA DatilMedia 2025-2035");
                return new SubCaCertDatil20252035();
            }
            if (ec.gob.firmadigital.libreria.utils.Utils.verifySignature(certificado, new SubCaCertDatilCortaDuracion20262036())) {
                System.out.println("SubCA DatilMedia Corta Duracion 2026-2036");
                return new SubCaCertDatilCortaDuracion20262036();
            }
        } catch (java.security.InvalidKeyException ex) {
            throw new EntidadCertificadoraNoValidaException("Entidad Certificadora no reconocida");
        }
        return null;
    }

    public static DatosUsuario getDatosUsuarioDatil(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        DatosUsuario datosUsuario = null;
        Certificado certificadoDatil = construir(certificado);
        if (certificadoDatil != null) {
            datosUsuario = new DatosUsuario();
            if (certificadoDatil instanceof CertificadoExtImplDatil) {
                if (certificadoDatil instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                            + certificadoPersonaNatural.getSegundoApellido());
                }
                if (certificadoDatil instanceof CertificadoPersonaJuridica certificadoPersonaJuridica) {
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
            if (certificadoDatil instanceof CertificadoSubjImpl) {
                if (certificadoDatil instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido());
                }
                if (certificadoDatil instanceof CertificadoMiembroEmpresa certificadoMiembroEmpresa) {
                    datosUsuario.setCedula(certificadoMiembroEmpresa.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoMiembroEmpresa.getNombres());
                    datosUsuario.setApellido(certificadoMiembroEmpresa.getPrimerApellido());
                    datosUsuario.setRuc(certificadoMiembroEmpresa.getRuc());
                    datosUsuario.setRazonSocial(certificadoMiembroEmpresa.getRazonSocial());
                    datosUsuario.setCargo(certificadoMiembroEmpresa.getCargo());
                }
                if (certificadoDatil instanceof CertificadoRepresentanteLegal certificadoRepresentanteLegal) {
                    datosUsuario.setCedula(certificadoRepresentanteLegal.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoRepresentanteLegal.getNombres());
                    datosUsuario.setApellido(certificadoRepresentanteLegal.getPrimerApellido());
                    datosUsuario.setRuc(certificadoRepresentanteLegal.getRuc());
                    datosUsuario.setRazonSocial(certificadoRepresentanteLegal.getRazonSocial());
                    datosUsuario.setCargo(certificadoRepresentanteLegal.getCargo());
                }
                if (certificadoDatil instanceof CertificadoSelloElectronico certificadoSelloElectronico) {
                    datosUsuario.setCedula(null);
                    datosUsuario.setNombre(certificadoSelloElectronico.getNombres());
                    datosUsuario.setApellido(certificadoSelloElectronico.getPrimerApellido());
                    datosUsuario.setCommonName(certificadoSelloElectronico.getCommonName());
                    datosUsuario.setRuc(certificadoSelloElectronico.getRuc());
                    datosUsuario.setRazonSocial(certificadoSelloElectronico.getRazonSocial());
                }
                if (certificadoDatil instanceof CertificadoSelladoTiempo certificadoSelladoTiempo) {
                    datosUsuario.setCommonName(certificadoSelladoTiempo.getCommonName());
                    datosUsuario.setRuc(certificadoSelladoTiempo.getRuc());
                    datosUsuario.setRazonSocial(certificadoSelladoTiempo.getRazonSocial());
                    datosUsuario.setCertificadoDigitalValido(true);
                }
            }
            datosUsuario.setCertificadoDigitalValido(true);
        }
        return datosUsuario;
    }

    private static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (ec.gob.firmadigital.libreria.certificate.CertUtils.hasExtensionMatchingPattern(certificado, "1.3.6.1.4.1", "3.1")) {
            if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
                return new CertificadoExtPersonaNaturalDatil(certificado);
            } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA)) {
                return new CertificadoExtPersonaJuridicaPrivadaDatil(certificado);
            } else {
                throw new EntidadCertificadoraNoValidaException("Certificado de DATILMEDIA S.A. sin categorizar!");
            }
        } else {//RESOLUCION-ARCOTEL-2024-0176
            if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
                return new CertificadoSubjPersonaNaturalDatil(certificado);
            } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL)) {
                return new CertificadoSubjRepresentanteLegalDatil(certificado);
            } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA)) {
                return new CertificadoSubjMiembroEmpresaDatil(certificado);
            } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_ELECTRONICO)) {
                return new CertificadoSubjSelloElectronicoDatil(certificado);
            } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_TIEMPO)) {
                return new CertificadoSubjSelladoTiempoDatil(certificado);
            } else {
                throw new EntidadCertificadoraNoValidaException("Certificado de DATILMEDIA S.A. sin categorizar!");
            }
        }
    }
}
