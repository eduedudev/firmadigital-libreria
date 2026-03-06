/*
 * Copyright (C) 2026 
 * Authors: Misael Fernández, SECURITY DATA SEGURIDAD EN DATOS Y FIRMA DIGITAL S.A.
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
package ec.gob.firmadigital.libreria.certificate.ec.securitydata;

import ec.gob.firmadigital.libreria.certificate.ec.securitydata.ext.*;
import ec.gob.firmadigital.libreria.certificate.ec.securitydata.subj.*;
import ec.gob.firmadigital.libreria.certificate.ec.subj.CertificadoSubjImpl;
import static ec.gob.firmadigital.libreria.certificate.ec.securitydata.CertificadoSecurityData.*;
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
 * @author Misael Fernández, SECURITY DATA SEGURIDAD EN DATOS Y FIRMA DIGITAL
 * S.A.
 */
public class CertificadoDataFactorySecurityData {

    public static DatosUsuario getDatosUsuarioSecurityData(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        DatosUsuario datosUsuario = null;
        if (esCertificadoDeSecurityData(certificado)) {
            datosUsuario = new DatosUsuario();
            Certificado certificadoSecurityData = construir(certificado);
            if (certificadoSecurityData instanceof CertificadoExtImplSecurityData) {
                if (certificadoSecurityData instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                            + certificadoPersonaNatural.getSegundoApellido());
                }
                if (certificadoSecurityData instanceof CertificadoFuncionarioPublico certificadoFuncionarioPublico) {
                    datosUsuario.setCedula(certificadoFuncionarioPublico.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoFuncionarioPublico.getNombres());
                    datosUsuario.setApellido(certificadoFuncionarioPublico.getPrimerApellido() + " "
                            + certificadoFuncionarioPublico.getSegundoApellido());
                    datosUsuario.setRuc(certificadoFuncionarioPublico.getRuc());
                    datosUsuario.setInstitucion(certificadoFuncionarioPublico.getInstitucion());
                    datosUsuario.setRazonSocial(certificadoFuncionarioPublico.getRazonSocial());
                    datosUsuario.setCargo(certificadoFuncionarioPublico.getCargo());
                }
                if (certificadoSecurityData instanceof CertificadoPersonaJuridica certificadoPersonaJuridica) {
                    datosUsuario.setCedula(certificadoPersonaJuridica.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaJuridica.getNombres());
                    datosUsuario.setApellido(certificadoPersonaJuridica.getPrimerApellido() + " "
                            + certificadoPersonaJuridica.getSegundoApellido());
                    datosUsuario.setRuc(certificadoPersonaJuridica.getRuc());
                    datosUsuario.setRazonSocial(certificadoPersonaJuridica.getRazonSocial());
                    datosUsuario.setCargo(certificadoPersonaJuridica.getCargo());
                }
                if (certificadoSecurityData instanceof CertificadoSelladoTiempo) {
                    datosUsuario.setCertificadoDigitalValido(true);
                }
            }
            //RESOLUCION-ARCOTEL-2024-0176
            if (certificadoSecurityData instanceof CertificadoSubjImpl) {
                if (certificadoSecurityData instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido());
                }
                if (certificadoSecurityData instanceof CertificadoMiembroEmpresa certificadoMiembroEmpresa) {
                    datosUsuario.setCedula(certificadoMiembroEmpresa.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoMiembroEmpresa.getNombres());
                    datosUsuario.setApellido(certificadoMiembroEmpresa.getPrimerApellido());
                    datosUsuario.setRuc(certificadoMiembroEmpresa.getRuc());
                    datosUsuario.setRazonSocial(certificadoMiembroEmpresa.getRazonSocial());
                    datosUsuario.setCargo(certificadoMiembroEmpresa.getCargo());
                }
                if (certificadoSecurityData instanceof CertificadoRepresentanteLegal certificadoRepresentanteLegal) {
                    datosUsuario.setCedula(certificadoRepresentanteLegal.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoRepresentanteLegal.getNombres());
                    datosUsuario.setApellido(certificadoRepresentanteLegal.getPrimerApellido());
                    datosUsuario.setRuc(certificadoRepresentanteLegal.getRuc());
                    datosUsuario.setRazonSocial(certificadoRepresentanteLegal.getRazonSocial());
                    datosUsuario.setCargo(certificadoRepresentanteLegal.getCargo());
                }
                if (certificadoSecurityData instanceof CertificadoSelloElectronico certificadoSelloElectronico) {
                    datosUsuario.setCedula(certificadoSelloElectronico.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoSelloElectronico.getNombres());
                    datosUsuario.setApellido(certificadoSelloElectronico.getPrimerApellido());
                    datosUsuario.setCommonName(certificadoSelloElectronico.getCommonName());
                }
                if (certificadoSecurityData instanceof CertificadoSelladoTiempo) {
                    datosUsuario.setCertificadoDigitalValido(true);
                }
            }
            datosUsuario.setCertificadoDigitalValido(true);
        }
        return datosUsuario;
    }

    private static boolean esCertificadoDeSecurityData(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_EMPRESA)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_LEGAL)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_FUNCIONARIO_PUBLICO)
                || certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL_PROFESIONAL)
                || certificateHasPolicy(certificado, Ext.OID_SELLADO_TIEMPO)
                //RESOLUCION-ARCOTEL-2024-0176
                || certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL_DSCF)
                || certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL)
                || certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL_DSCF)
                || certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA)
                || certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA_DSCF)
                || certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_ELECTRONICO)
                || certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_ELECTRONICO_DSCF)
                || certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_TIEMPO_DSCF));
    }

    private static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoExtPersonaNaturalSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_EMPRESA)) {
            return new CertificadoExtPersonaJuridicaSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_LEGAL)) {
            return new CertificadoExtRepresentanteLegalSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)) {
            return new CertificadoExtMiembroEmpresaSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_FUNCIONARIO_PUBLICO)) {
            return new CertificadoExtFuncionarioPublicoSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL_PROFESIONAL)) {
            return new CertificadoExtPersonaNaturalSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Ext.OID_SELLADO_TIEMPO)) {
            return new CertificadoExtSelladoTiempoSecurityData(certificado);
        } //RESOLUCION-ARCOTEL-2024-0176
        else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoSubjPersonaNaturalSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL_DSCF)) {
            return new CertificadoSubjPersonaNaturalSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL)) {
            return new CertificadoSubjRepresentanteLegalSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL_DSCF)) {
            return new CertificadoSubjRepresentanteLegalSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA)) {
            return new CertificadoSubjMiembroEmpresaSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA_DSCF)) {
            return new CertificadoSubjMiembroEmpresaSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_ELECTRONICO)) {
            return new CertificadoSubjSelloElectronicoSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_ELECTRONICO_DSCF)) {
            return new CertificadoSubjSelloElectronicoSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_TIEMPO_DSCF)) {
            return new CertificadoSubjSelladoTiempoSecurityData(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de SECURITY DATA SEGURIDAD EN DATOS Y FIRMA DIGITAL S.A. sin categorizar!");
        }
    }
}
