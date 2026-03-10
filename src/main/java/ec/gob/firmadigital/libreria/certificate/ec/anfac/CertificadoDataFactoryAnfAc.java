/*
 * Copyright (C) 2026 
 * Authors: Misael Fernández, ANFAC AUTORIDAD DE CERTIFICACION ECUADOR C.A.
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
package ec.gob.firmadigital.libreria.certificate.ec.anfac;

import ec.gob.firmadigital.libreria.certificate.ec.anfac.ext.*;
import ec.gob.firmadigital.libreria.certificate.ec.anfac.subj.*;
import ec.gob.firmadigital.libreria.certificate.ec.subj.CertificadoSubjImpl;
import static ec.gob.firmadigital.libreria.certificate.ec.anfac.CertificadoAnfAc.*;
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
 * @author Misael Fernández, ANFAC AUTORIDAD DE CERTIFICACION ECUADOR C.A.
 */
public class CertificadoDataFactoryAnfAc {

    public static DatosUsuario getDatosUsuarioAnfAc(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        DatosUsuario datosUsuario = null;
        if (esCertificadoDeAnfAc18332(certificado)) {
            datosUsuario = new DatosUsuario();
            Certificado certificadoAnfAc18332 = construir18332(certificado);
            if (certificadoAnfAc18332 instanceof CertificadoExtImplAnfAc_18332) {
                if (certificadoAnfAc18332 instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                            + certificadoPersonaNatural.getSegundoApellido());
                }
                if (certificadoAnfAc18332 instanceof CertificadoFuncionarioPublico certificadoFuncionarioPublico) {
                    datosUsuario.setCedula(certificadoFuncionarioPublico.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoFuncionarioPublico.getNombres());
                    datosUsuario.setApellido(certificadoFuncionarioPublico.getPrimerApellido() + " "
                            + certificadoFuncionarioPublico.getSegundoApellido());
                    datosUsuario.setRuc(certificadoFuncionarioPublico.getRuc());
                    datosUsuario.setInstitucion(certificadoFuncionarioPublico.getInstitucion());
                    datosUsuario.setCargo(certificadoFuncionarioPublico.getCargo());
                }
                if (certificadoAnfAc18332 instanceof CertificadoPersonaJuridica certificadoPersonaJuridica) {
                    datosUsuario.setCedula(certificadoPersonaJuridica.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaJuridica.getNombres());
                    datosUsuario.setApellido(certificadoPersonaJuridica.getPrimerApellido() + " "
                            + certificadoPersonaJuridica.getSegundoApellido());
                    datosUsuario.setRuc(certificadoPersonaJuridica.getRuc());
                    datosUsuario.setRazonSocial(certificadoPersonaJuridica.getRazonSocial());
                    datosUsuario.setCargo(certificadoPersonaJuridica.getCargo());
                }
            }
            datosUsuario.setCertificadoDigitalValido(true);
        }

        if (esCertificadoDeAnfAc37442(certificado)) {
            datosUsuario = new DatosUsuario();
            Certificado certificadoAnfAc37442 = construir37442(certificado);
            if (certificadoAnfAc37442 instanceof CertificadoExtImplAnfAc_37442) {
                if (certificadoAnfAc37442 instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                            + certificadoPersonaNatural.getSegundoApellido());
                }
                if (certificadoAnfAc37442 instanceof CertificadoFuncionarioPublico certificadoFuncionarioPublico) {
                    datosUsuario.setCedula(certificadoFuncionarioPublico.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoFuncionarioPublico.getNombres());
                    datosUsuario.setApellido(certificadoFuncionarioPublico.getPrimerApellido() + " "
                            + certificadoFuncionarioPublico.getSegundoApellido());
                    datosUsuario.setRuc(certificadoFuncionarioPublico.getRuc());
                    datosUsuario.setInstitucion(certificadoFuncionarioPublico.getInstitucion());
                    datosUsuario.setCargo(certificadoFuncionarioPublico.getCargo());
                }
                if (certificadoAnfAc37442 instanceof CertificadoPersonaJuridica certificadoPersonaJuridica) {
                    datosUsuario.setCedula(certificadoPersonaJuridica.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaJuridica.getNombres());
                    datosUsuario.setApellido(certificadoPersonaJuridica.getPrimerApellido() + " "
                            + certificadoPersonaJuridica.getSegundoApellido());
                    datosUsuario.setRuc(certificadoPersonaJuridica.getRuc());
                    datosUsuario.setRazonSocial(certificadoPersonaJuridica.getRazonSocial());
                    datosUsuario.setCargo(certificadoPersonaJuridica.getCargo());
                }
                if (certificadoAnfAc37442 instanceof CertificadoSelladoTiempo certificadoSelladoTiempo) {
                    datosUsuario.setCommonName(certificadoSelladoTiempo.getCommonName());
                    datosUsuario.setRuc(certificadoSelladoTiempo.getRuc());
                    datosUsuario.setRazonSocial(certificadoSelladoTiempo.getRazonSocial());
                    datosUsuario.setCertificadoDigitalValido(true);
                }
            }
            // RESOLUCION-ARCOTEL-2024-0176
            if (certificadoAnfAc37442 instanceof CertificadoSubjImpl) {
                if (certificadoAnfAc37442 instanceof CertificadoPersonaNatural certificadoPersonaNatural) {
                    datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                    datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                            + certificadoPersonaNatural.getSegundoApellido());
                }
                if (certificadoAnfAc37442 instanceof CertificadoMiembroEmpresa certificadoMiembroEmpresa) {
                    datosUsuario.setCedula(certificadoMiembroEmpresa.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoMiembroEmpresa.getNombres());
                    datosUsuario.setApellido(certificadoMiembroEmpresa.getPrimerApellido() + " "
                            + certificadoMiembroEmpresa.getSegundoApellido());
                    datosUsuario.setRuc(certificadoMiembroEmpresa.getRuc());
                    datosUsuario.setRazonSocial(certificadoMiembroEmpresa.getRazonSocial());
                    datosUsuario.setCargo(certificadoMiembroEmpresa.getCargo());
                }
                if (certificadoAnfAc37442 instanceof CertificadoRepresentanteLegal certificadoRepresentanteLegal) {
                    datosUsuario.setCedula(certificadoRepresentanteLegal.getCedulaPasaporte());
                    datosUsuario.setNombre(certificadoRepresentanteLegal.getNombres());
                    datosUsuario.setApellido(certificadoRepresentanteLegal.getPrimerApellido() + " "
                            + certificadoRepresentanteLegal.getSegundoApellido());
                    datosUsuario.setRuc(certificadoRepresentanteLegal.getRuc());
                    datosUsuario.setRazonSocial(certificadoRepresentanteLegal.getRazonSocial());
                    datosUsuario.setCargo(certificadoRepresentanteLegal.getCargo());
                }
                if (certificadoAnfAc37442 instanceof CertificadoSelloElectronico certificadoSelloElectronico) {
                    datosUsuario.setCedula(null);
                    datosUsuario.setNombre(certificadoSelloElectronico.getNombres());
                    datosUsuario.setApellido(certificadoSelloElectronico.getPrimerApellido());
                    datosUsuario.setCommonName(certificadoSelloElectronico.getCommonName());
                    datosUsuario.setRuc(certificadoSelloElectronico.getRuc());
                    datosUsuario.setRazonSocial(certificadoSelloElectronico.getRazonSocial());
                }
                if (certificadoAnfAc37442 instanceof CertificadoSelladoTiempo certificadoSelladoTiempo) {
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

    private static boolean esCertificadoDeAnfAc18332(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, Ext18332.OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Ext18332.OID_TIPO_PERSONA_JURIDICA)
                || certificateHasPolicy(certificado, Ext18332.OID_TIPO_FUNCIONARIO_PUBLICO));
    }

    private static Certificado construir18332(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, Ext18332.OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoExtPersonaNaturalAnfAc_18332(certificado);
        } else if (certificateHasPolicy(certificado, Ext18332.OID_TIPO_PERSONA_JURIDICA)) {
            return new CertificadoExtPersonaJuridicaAnfAc_18332(certificado);
        } else if (certificateHasPolicy(certificado, Ext18332.OID_TIPO_FUNCIONARIO_PUBLICO)) {
            return new CertificadoExtFuncionarioPublicoAnfAc_18332(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de ANFAC AUTORIDAD DE CERTIFICACION ECUADOR C.A. 18332 sin categorizar!");
        }
    }

    private static boolean esCertificadoDeAnfAc37442(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, Ext37442.OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Ext37442.OID_TIPO_PERSONA_NATURAL_TOKEN)
                || certificateHasPolicy(certificado, Ext37442.OID_TIPO_PERSONA_JURIDICA)
                || certificateHasPolicy(certificado, Ext37442.OID_TIPO_PERSONA_JURIDICA_TOKEN)
                || certificateHasPolicy(certificado, Ext37442.OID_TIPO_FUNCIONARIO_PUBLICO)
                || certificateHasPolicy(certificado, Ext37442.OID_TIPO_FUNCIONARIO_PUBLICO_TOKEN)
                || certificateHasPolicy(certificado, Ext37442.OID_SELLADO_TIEMPO)
                // RESOLUCION-ARCOTEL-2024-0176
                || certificateHasPolicy(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA)
                || certificateHasPolicy(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL)
                || certificateHasPolicy(certificado, Subj.OID_SELLADO_TIEMPO)
                || certificateHasPolicy(certificado, Subj.OID_SELLO_ELECTRONICO));
    }

    private static Certificado construir37442(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, Ext37442.OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoExtPersonaNaturalAnfAc_37442(certificado);
        } else if (certificateHasPolicy(certificado, Ext37442.OID_TIPO_PERSONA_NATURAL_TOKEN)) {
            return new CertificadoExtPersonaNaturalAnfAc_37442(certificado);
        } else if (certificateHasPolicy(certificado, Ext37442.OID_TIPO_PERSONA_JURIDICA)) {
            return new CertificadoExtPersonaJuridicaAnfAc_37442(certificado);
        } else if (certificateHasPolicy(certificado, Ext37442.OID_TIPO_PERSONA_JURIDICA_TOKEN)) {
            return new CertificadoExtPersonaJuridicaAnfAc_37442(certificado);
        } else if (certificateHasPolicy(certificado, Ext37442.OID_TIPO_FUNCIONARIO_PUBLICO)) {
            return new CertificadoExtFuncionarioPublicoAnfAc_37442(certificado);
        } else if (certificateHasPolicy(certificado, Ext37442.OID_TIPO_FUNCIONARIO_PUBLICO_TOKEN)) {
            return new CertificadoExtFuncionarioPublicoAnfAc_37442(certificado);
        } else if (certificateHasPolicy(certificado, Ext37442.OID_SELLADO_TIEMPO)) {
            return new CertificadoExtSelladoTiempoAnfAc_37442(certificado);
        } // RESOLUCION-ARCOTEL-2024-0176
        else if (certificateHasPolicy(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL)) {
            return new CertificadoSubjPersonaNaturalAnfAc(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA)) {
            return new CertificadoSubjMiembroEmpresaAnfAc(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL)) {
            return new CertificadoSubjRepresentanteLegalAnfAc(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_SELLADO_TIEMPO)) {
            return new CertificadoSubjSelladoTiempoAnfAc(certificado);
        } else if (certificateHasPolicy(certificado, Subj.OID_SELLO_ELECTRONICO)) {
            return new CertificadoSubjSelloElectronicoAnfAc(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de ANFAC AUTORIDAD DE CERTIFICACION ECUADOR C.A. 37442 sin categorizar!");
        }
    }
}
