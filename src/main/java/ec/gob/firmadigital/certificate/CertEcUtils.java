/*
 * Copyright (C) 2020 
 * Authors: Ricardo Arguello, Misael Fernández
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
package ec.gob.firmadigital.certificate;

import java.security.cert.X509Certificate;

import ec.gob.firmadigital.certificate.ec.CertificadoFuncionarioPublico;
import ec.gob.firmadigital.certificate.ec.CertificadoMiembroEmpresa;
import ec.gob.firmadigital.certificate.ec.CertificadoPersonaJuridica;
import ec.gob.firmadigital.certificate.ec.CertificadoPersonaNatural;
import ec.gob.firmadigital.certificate.ec.CertificadoRepresentanteLegal;
import ec.gob.firmadigital.certificate.ec.CertificadoSelladoTiempo;
import ec.gob.firmadigital.certificate.ec.anfac.AnfAc18332SubCaCert20162032;
import ec.gob.firmadigital.certificate.ec.anfac.AnfAc37442SubCaCert20192029;
import ec.gob.firmadigital.certificate.ec.anfac.CertificadoAnfAc18332;
import ec.gob.firmadigital.certificate.ec.anfac.CertificadoAnfAc18332Factory;
import ec.gob.firmadigital.certificate.ec.anfac.CertificadoAnfAc37442;
import ec.gob.firmadigital.certificate.ec.anfac.CertificadoAnfAc37442Factory;
import ec.gob.firmadigital.certificate.ec.argosdata.ArgosDataSubCaCert;
import ec.gob.firmadigital.certificate.ec.argosdata.CertificadoArgosData;
import ec.gob.firmadigital.certificate.ec.argosdata.CertificadoArgosDataFactory;
import ec.gob.firmadigital.certificate.ec.argosdata.CertificadoPersonaNaturalArgosData;
import ec.gob.firmadigital.certificate.ec.argosdata.CertificadoRepresentanteLegalArgosData;
import ec.gob.firmadigital.certificate.ec.bce.BceSubCaCert20112021;
import ec.gob.firmadigital.certificate.ec.bce.BceSubCaCert20192029;
import ec.gob.firmadigital.certificate.ec.bce.CertificadoBancoCentral;
import ec.gob.firmadigital.certificate.ec.bce.CertificadoBancoCentralFactory;
import ec.gob.firmadigital.certificate.ec.cj.CertificadoConsejoJudicatura;
import ec.gob.firmadigital.certificate.ec.cj.CertificadoConsejoJudicaturaDataFactory;
import ec.gob.firmadigital.certificate.ec.cj.CertificadoDepartamentoEmpresaConsejoJudicatura;
import ec.gob.firmadigital.certificate.ec.cj.CertificadoEmpresaConsejoJudicatura;
import ec.gob.firmadigital.certificate.ec.cj.CertificadoMiembroEmpresaConsejoJudicatura;
import ec.gob.firmadigital.certificate.ec.cj.CertificadoPersonaJuridicaPrivadaConsejoJudicatura;
import ec.gob.firmadigital.certificate.ec.cj.CertificadoPersonaJuridicaPublicaConsejoJudicatura;
import ec.gob.firmadigital.certificate.ec.cj.CertificadoPersonaNaturalConsejoJudicatura;
import ec.gob.firmadigital.certificate.ec.cj.ConsejoJudicaturaSubCaCert;
import ec.gob.firmadigital.certificate.ec.datil.CertificadoDatil;
import ec.gob.firmadigital.certificate.ec.datil.CertificadoDatilDataFactory;
import ec.gob.firmadigital.certificate.ec.datil.CertificadoMiembroEmpresaDatil;
import ec.gob.firmadigital.certificate.ec.datil.CertificadoPersonaJuridicaPrivadaDatil;
import ec.gob.firmadigital.certificate.ec.datil.CertificadoPersonaNaturalDatil;
import ec.gob.firmadigital.certificate.ec.datil.CertificadoRepresentanteLegalDatil;
import ec.gob.firmadigital.certificate.ec.datil.DatilSubCaCert20212031;
import ec.gob.firmadigital.certificate.ec.digercic.CertificadoDigercic;
import ec.gob.firmadigital.certificate.ec.digercic.CertificadoDigercicFactory;
import ec.gob.firmadigital.certificate.ec.digercic.DigercicSubCaCert20212031;
import ec.gob.firmadigital.certificate.ec.eclipsoft.CertificadoEclipsoft;
import ec.gob.firmadigital.certificate.ec.eclipsoft.CertificadoEclipsoftDataFactory;
import ec.gob.firmadigital.certificate.ec.eclipsoft.CertificadoMiembroEmpresaEclipsoft;
import ec.gob.firmadigital.certificate.ec.eclipsoft.CertificadoPersonaJuridicaPrivadaEclipsoft;
import ec.gob.firmadigital.certificate.ec.eclipsoft.CertificadoPersonalNaturalEclipsoft;
import ec.gob.firmadigital.certificate.ec.eclipsoft.CertificadoRepresentanteLegalEclipsoft;
import ec.gob.firmadigital.certificate.ec.lazzate.CertificadoLazzate;
import ec.gob.firmadigital.certificate.ec.lazzate.CertificadoLazzateDataFactory;
import ec.gob.firmadigital.certificate.ec.lazzate.LazzateSubCaCert;
import ec.gob.firmadigital.certificate.ec.securitydata.CertificadoSecurityData;
import ec.gob.firmadigital.certificate.ec.securitydata.CertificadoSecurityDataFactory;
import ec.gob.firmadigital.certificate.ec.securitydata.SecurityDataSubCaCert20112026;
import ec.gob.firmadigital.certificate.ec.securitydata.SecurityDataSubCaCert20192031;
import ec.gob.firmadigital.certificate.ec.securitydata.SecurityDataSubCaCert20202039;
import ec.gob.firmadigital.certificate.ec.uanataca.CertificadoMiembroEmpresaUanataca;
import ec.gob.firmadigital.certificate.ec.uanataca.CertificadoPersonaJuridicaPrivadaUanataca;
import ec.gob.firmadigital.certificate.ec.uanataca.CertificadoPersonaNaturalUanataca;
import ec.gob.firmadigital.certificate.ec.uanataca.CertificadoRepresentanteLegalUanataca;
import ec.gob.firmadigital.certificate.ec.uanataca.CertificadoUanataca;
import ec.gob.firmadigital.certificate.ec.uanataca.CertificadoUanatacaDataFactory;
import ec.gob.firmadigital.certificate.ec.uanataca.UanatacaSubCaCert0120162029;
import ec.gob.firmadigital.certificate.ec.uanataca.UanatacaSubCaCert0220162029;
import ec.gob.firmadigital.certificate.to.DatosUsuario;
import ec.gob.firmadigital.exceptions.EntidadCertificadoraNoValidaException;
import ec.gob.firmadigital.utils.Utils;

/**
 * Validar diferentes certificados digitales acreditados por ARCOTEL
 *
 * @author mfernandez
 */
public class CertEcUtils {

    public static final String UANATACA_NAME = "UANATACA S.A.";
    public static final String ECLIPSOFT_NAME = "ECLIPSOFT S.A.";
    public static final String DATIL_NAME = "DATILMEDIA S.A.";
    public static final String AGOSDATA_NAME = "ARGOSDATA CA";
    public static final String LAZZATE_NAME = "LAZZATE CIA. LTDA";

    public static X509Certificate getRootCertificate(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        String entidadCertStr = getNombreCA(certificado);

        switch (entidadCertStr) {
            case "Banco Central del Ecuador": {
                try {
                    if (ec.gob.firmadigital.utils.Utils.verifySignature(certificado, new BceSubCaCert20112021())) {
                        System.out.println("BceSubCaCert 2011-2021");
                        return new BceSubCaCert20112021();
                    }
                    if (ec.gob.firmadigital.utils.Utils.verifySignature(certificado, new BceSubCaCert20192029())) {
                        System.out.println("BceSubCaCert 2019-2029");
                        return new BceSubCaCert20192029();
                    }
                    return null;
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            case "Security Data": {
                try {
                    if (ec.gob.firmadigital.utils.Utils.verifySignature(certificado, new SecurityDataSubCaCert20112026())) {
                        System.out.println("SecurityDataSubCaCert");
                        return new SecurityDataSubCaCert20112026();
                    }
                    if (ec.gob.firmadigital.utils.Utils.verifySignature(certificado, new SecurityDataSubCaCert20192031())) {
                        System.out.println("SecurityDataSubCaCert 2019-2031");
                        return new SecurityDataSubCaCert20192031();
                    }
                    if (ec.gob.firmadigital.utils.Utils.verifySignature(certificado, new SecurityDataSubCaCert20202039())) {
                        System.out.println("SecurityDataSubCaCert 2020-2032");
                        return new SecurityDataSubCaCert20202039();
                    }
                    return null;
                } catch (java.security.InvalidKeyException ex) {
                    //TODO
                }
            }
            case "Consejo de la Judicatura":
                return new ConsejoJudicaturaSubCaCert();
            case "Anf AC":
                try {
                if (ec.gob.firmadigital.utils.Utils.verifySignature(certificado, new AnfAc18332SubCaCert20162032())) {
                    System.out.println("Anf 2016-2032");
                    return new AnfAc18332SubCaCert20162032();
                }
                if (ec.gob.firmadigital.utils.Utils.verifySignature(certificado, new AnfAc37442SubCaCert20192029())) {
                    System.out.println("Anf 2019-2029");
                    return new AnfAc37442SubCaCert20192029();
                }
                return null;
            } catch (java.security.InvalidKeyException ex) {
                //TODO
            }
            case "Dirección General de Registro Civil, Identificación y Cedulación": {
                return new DigercicSubCaCert20212031();
            }
            case UANATACA_NAME:
                try {
                if (ec.gob.firmadigital.utils.Utils.verifySignature(certificado, new UanatacaSubCaCert0120162029())) {
                    System.out.println("Uanataca 2016-2029");
                    return new UanatacaSubCaCert0120162029();
                }
                if (ec.gob.firmadigital.utils.Utils.verifySignature(certificado, new UanatacaSubCaCert0220162029())) {
                    System.out.println("Uanataca 2016-2029");
                    return new UanatacaSubCaCert0220162029();
                }
                return null;
            } catch (java.security.InvalidKeyException ex) {
                //TODO
            }
            case DATIL_NAME: {
                return new DatilSubCaCert20212031();
            }
            case AGOSDATA_NAME: {
                return new ArgosDataSubCaCert();
            }
            case LAZZATE_NAME: {
                return new LazzateSubCaCert();
            }

            default:
                throw new EntidadCertificadoraNoValidaException("Entidad Certificadora no reconocida");
        }
    }

    //TODO poner los nombres como constantes
    public static String getNombreCA(X509Certificate certificado) {
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains("BANCO CENTRAL DEL ECUADOR")) {
            return "Banco Central del Ecuador";
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains("SECURITY DATA")) {
            return "Security Data";
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains("CONSEJO DE LA JUDICATURA")) {
            return "Consejo de la Judicatura";
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains("ANF")) {
            return "Anf AC";
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains("DIRECCIÓN GENERAL DE REGISTRO CIVIL")) {
            return "Dirección General de Registro Civil, Identificación y Cedulación";
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(UANATACA_NAME)) {
            return UANATACA_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(DATIL_NAME)) {
            return DATIL_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(AGOSDATA_NAME)) {
            return AGOSDATA_NAME;
        }
        if (certificado.getIssuerX500Principal().getName().toUpperCase().contains(LAZZATE_NAME)) {
            return LAZZATE_NAME;
        }

        return "Entidad no reconocida " + certificado.getIssuerX500Principal().getName();
    }

    //TODO poner los nombres como constantes
    public static DatosUsuario getDatosUsuarios(X509Certificate certificado) {
        DatosUsuario datosUsuario = new DatosUsuario();
        datosUsuario.setSelladoTiempo(false);
        if (CertificadoBancoCentralFactory.esCertificadoDelBancoCentral(certificado)) {
            CertificadoBancoCentral certificadoBancoCentral = CertificadoBancoCentralFactory.construir(certificado);
            if (certificadoBancoCentral instanceof CertificadoFuncionarioPublico) {
                CertificadoFuncionarioPublico certificadoFuncionarioPublico = (CertificadoFuncionarioPublico) certificadoBancoCentral;
                datosUsuario.setCedula(certificadoFuncionarioPublico.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoFuncionarioPublico.getNombres());
                datosUsuario.setApellido(certificadoFuncionarioPublico.getPrimerApellido() + " "
                        + certificadoFuncionarioPublico.getSegundoApellido());
                datosUsuario.setInstitucion(certificadoFuncionarioPublico.getInstitucion());
                datosUsuario.setCargo(certificadoFuncionarioPublico.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoBancoCentral instanceof CertificadoMiembroEmpresa) {
                CertificadoMiembroEmpresa certificadoMiembroEmpresa = (CertificadoMiembroEmpresa) certificadoBancoCentral;
                datosUsuario.setCedula(certificadoMiembroEmpresa.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoMiembroEmpresa.getNombres());
                datosUsuario.setApellido(certificadoMiembroEmpresa.getPrimerApellido() + " "
                        + certificadoMiembroEmpresa.getSegundoApellido());
                datosUsuario.setCargo(certificadoMiembroEmpresa.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoBancoCentral instanceof CertificadoPersonaJuridica) {
                CertificadoPersonaJuridica certificadoPersonaJuridica = (CertificadoPersonaJuridica) certificadoBancoCentral;
                datosUsuario.setCedula(certificadoPersonaJuridica.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaJuridica.getNombres());
                datosUsuario.setApellido(certificadoPersonaJuridica.getPrimerApellido() + " "
                        + certificadoPersonaJuridica.getSegundoApellido());
                datosUsuario.setCargo(certificadoPersonaJuridica.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoBancoCentral instanceof CertificadoPersonaNatural) {
                CertificadoPersonaNatural certificadoPersonaNatural = (CertificadoPersonaNatural) certificadoBancoCentral;
                datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                        + certificadoPersonaNatural.getSegundoApellido());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoBancoCentral instanceof CertificadoRepresentanteLegal) {
                CertificadoRepresentanteLegal certificadoRepresentanteLegal = (CertificadoRepresentanteLegal) certificadoBancoCentral;
                datosUsuario.setCedula(certificadoRepresentanteLegal.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoRepresentanteLegal.getNombres());
                datosUsuario.setApellido(certificadoRepresentanteLegal.getPrimerApellido() + " "
                        + certificadoRepresentanteLegal.getSegundoApellido());
                datosUsuario.setCargo(certificadoRepresentanteLegal.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoBancoCentral instanceof CertificadoSelladoTiempo) {
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            datosUsuario.setEntidadCertificadora("Banco Central del Ecuador");
            datosUsuario.setCertificadoDigitalValido(true);
            return datosUsuario;
        }

        if (CertificadoConsejoJudicaturaDataFactory.esCertificadoDelConsejoJudicatura(certificado)) {
            CertificadoConsejoJudicatura certificadoConsejoJudicatura = CertificadoConsejoJudicaturaDataFactory.construir(certificado);
            if (certificadoConsejoJudicatura instanceof CertificadoDepartamentoEmpresaConsejoJudicatura) {
                CertificadoDepartamentoEmpresaConsejoJudicatura certificadoDepartamentoEmpresaConsejoJudicatura;
                certificadoDepartamentoEmpresaConsejoJudicatura = (CertificadoDepartamentoEmpresaConsejoJudicatura) certificadoConsejoJudicatura;

                datosUsuario.setCedula(certificadoDepartamentoEmpresaConsejoJudicatura.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoDepartamentoEmpresaConsejoJudicatura.getNombres());
                datosUsuario.setApellido(certificadoDepartamentoEmpresaConsejoJudicatura.getPrimerApellido() + " "
                        + certificadoDepartamentoEmpresaConsejoJudicatura.getSegundoApellido());
                datosUsuario.setCargo(certificadoDepartamentoEmpresaConsejoJudicatura.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoConsejoJudicatura instanceof CertificadoEmpresaConsejoJudicatura) {
                CertificadoEmpresaConsejoJudicatura certificadoEmpresaConsejoJudicatura = (CertificadoEmpresaConsejoJudicatura) certificadoConsejoJudicatura;
                datosUsuario.setCedula(certificadoEmpresaConsejoJudicatura.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoEmpresaConsejoJudicatura.getNombres());
                datosUsuario.setApellido(certificadoEmpresaConsejoJudicatura.getPrimerApellido() + " "
                        + certificadoEmpresaConsejoJudicatura.getSegundoApellido());
                datosUsuario.setCargo(certificadoEmpresaConsejoJudicatura.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoConsejoJudicatura instanceof CertificadoMiembroEmpresaConsejoJudicatura) {
                CertificadoMiembroEmpresaConsejoJudicatura certificadoMiembroEmpresaConsejoJudicatura = (CertificadoMiembroEmpresaConsejoJudicatura) certificadoConsejoJudicatura;
                datosUsuario.setCedula(certificadoMiembroEmpresaConsejoJudicatura.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoMiembroEmpresaConsejoJudicatura.getNombres());
                datosUsuario.setApellido(certificadoMiembroEmpresaConsejoJudicatura.getPrimerApellido() + " "
                        + certificadoMiembroEmpresaConsejoJudicatura.getSegundoApellido());
                datosUsuario.setCargo(certificadoMiembroEmpresaConsejoJudicatura.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoConsejoJudicatura instanceof CertificadoPersonaJuridicaPrivadaConsejoJudicatura) {
                CertificadoPersonaJuridicaPrivadaConsejoJudicatura certificadoPersonaJuridicaPrivadaConsejoJudicatura = (CertificadoPersonaJuridicaPrivadaConsejoJudicatura) certificadoConsejoJudicatura;
                datosUsuario.setCedula(certificadoPersonaJuridicaPrivadaConsejoJudicatura.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaJuridicaPrivadaConsejoJudicatura.getNombres());
                datosUsuario.setApellido(certificadoPersonaJuridicaPrivadaConsejoJudicatura.getPrimerApellido() + " "
                        + certificadoPersonaJuridicaPrivadaConsejoJudicatura.getSegundoApellido());
                datosUsuario.setCargo(datosUsuario.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoConsejoJudicatura instanceof CertificadoPersonaJuridicaPublicaConsejoJudicatura) {
                CertificadoPersonaJuridicaPublicaConsejoJudicatura certificadoPersonaJuridicaPublicaConsejoJudicatura = (CertificadoPersonaJuridicaPublicaConsejoJudicatura) certificadoConsejoJudicatura;
                datosUsuario.setCedula(certificadoPersonaJuridicaPublicaConsejoJudicatura.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaJuridicaPublicaConsejoJudicatura.getNombres());
                datosUsuario.setApellido(certificadoPersonaJuridicaPublicaConsejoJudicatura.getPrimerApellido() + " "
                        + certificadoPersonaJuridicaPublicaConsejoJudicatura.getSegundoApellido());
                datosUsuario.setCargo(certificadoPersonaJuridicaPublicaConsejoJudicatura.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoConsejoJudicatura instanceof CertificadoPersonaNaturalConsejoJudicatura) {
                CertificadoPersonaNaturalConsejoJudicatura certificadoPersonaNaturalConsejoJudicatura = (CertificadoPersonaNaturalConsejoJudicatura) certificadoConsejoJudicatura;
                datosUsuario.setCedula(certificadoPersonaNaturalConsejoJudicatura.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaNaturalConsejoJudicatura.getNombres());
                datosUsuario.setApellido(certificadoPersonaNaturalConsejoJudicatura.getPrimerApellido() + " "
                        + certificadoPersonaNaturalConsejoJudicatura.getSegundoApellido());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoConsejoJudicatura instanceof CertificadoSelladoTiempo) {
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            datosUsuario.setEntidadCertificadora("Consejo de la Judicatura");
            datosUsuario.setCertificadoDigitalValido(true);
            return datosUsuario;
        }

        if (CertificadoSecurityDataFactory.esCertificadoDeSecurityData(certificado)) {
            CertificadoSecurityData certificadoSecurityData = CertificadoSecurityDataFactory.construir(certificado);
            if (certificadoSecurityData instanceof CertificadoFuncionarioPublico) {
                CertificadoFuncionarioPublico certificadoFuncionarioPublico = (CertificadoFuncionarioPublico) certificadoSecurityData;
                datosUsuario.setCedula(certificadoFuncionarioPublico.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoFuncionarioPublico.getNombres());
                datosUsuario.setApellido(certificadoFuncionarioPublico.getPrimerApellido() + " "
                        + certificadoFuncionarioPublico.getSegundoApellido());
                datosUsuario.setCargo(certificadoFuncionarioPublico.getCargo());
                datosUsuario.setInstitucion(certificadoFuncionarioPublico.getInstitucion());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoSecurityData instanceof CertificadoPersonaJuridica) {
                CertificadoPersonaJuridica certificadoPersonaJuridica = (CertificadoPersonaJuridica) certificadoSecurityData;
                datosUsuario.setCedula(certificadoPersonaJuridica.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaJuridica.getNombres());
                datosUsuario.setApellido(certificadoPersonaJuridica.getPrimerApellido() + " "
                        + certificadoPersonaJuridica.getSegundoApellido());
                datosUsuario.setCargo(certificadoPersonaJuridica.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }

            if (certificadoSecurityData instanceof CertificadoPersonaNatural) {
                CertificadoPersonaNatural certificadoPersonaNatural = (CertificadoPersonaNatural) certificadoSecurityData;
                datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                        + certificadoPersonaNatural.getSegundoApellido());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoSecurityData instanceof CertificadoSelladoTiempo) {
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            datosUsuario.setEntidadCertificadora("Security Data");
            datosUsuario.setCertificadoDigitalValido(true);
            return datosUsuario;
        }

        if (CertificadoAnfAc18332Factory.esCertificadoDeAnfAc18332(certificado)) {
            CertificadoAnfAc18332 certificadoAnfAc18332 = CertificadoAnfAc18332Factory.construir(certificado);
            if (certificadoAnfAc18332 instanceof CertificadoFuncionarioPublico) {
                CertificadoFuncionarioPublico certificadoFuncionarioPublico = (CertificadoFuncionarioPublico) certificadoAnfAc18332;

                datosUsuario.setCedula(certificadoFuncionarioPublico.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoFuncionarioPublico.getNombres());
                datosUsuario.setApellido(certificadoFuncionarioPublico.getPrimerApellido() + " "
                        + certificadoFuncionarioPublico.getSegundoApellido());
                datosUsuario.setCargo(certificadoFuncionarioPublico.getCargo());
                datosUsuario.setInstitucion(certificadoFuncionarioPublico.getInstitucion());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoAnfAc18332 instanceof CertificadoPersonaJuridica) {
                CertificadoPersonaJuridica certificadoPersonaJuridica = (CertificadoPersonaJuridica) certificadoAnfAc18332;
                datosUsuario.setCedula(certificadoPersonaJuridica.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaJuridica.getNombres());
                datosUsuario.setApellido(certificadoPersonaJuridica.getPrimerApellido() + " "
                        + certificadoPersonaJuridica.getSegundoApellido());
                datosUsuario.setCargo(certificadoPersonaJuridica.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }

            if (certificadoAnfAc18332 instanceof CertificadoPersonaNatural) {
                CertificadoPersonaNatural certificadoPersonaNatural = (CertificadoPersonaNatural) certificadoAnfAc18332;
                datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                        + certificadoPersonaNatural.getSegundoApellido());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoAnfAc18332 instanceof CertificadoSelladoTiempo) {
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            datosUsuario.setEntidadCertificadora("Anf AC");
            datosUsuario.setCertificadoDigitalValido(true);
            return datosUsuario;
        }

        if (CertificadoAnfAc37442Factory.esCertificadoDeAnfAc37442(certificado)) {
            CertificadoAnfAc37442 certificadoAnfAc37442 = CertificadoAnfAc37442Factory.construir(certificado);
            if (certificadoAnfAc37442 instanceof CertificadoFuncionarioPublico) {
                CertificadoFuncionarioPublico certificadoFuncionarioPublico = (CertificadoFuncionarioPublico) certificadoAnfAc37442;

                datosUsuario.setCedula(certificadoFuncionarioPublico.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoFuncionarioPublico.getNombres());
                datosUsuario.setApellido(certificadoFuncionarioPublico.getPrimerApellido() + " "
                        + certificadoFuncionarioPublico.getSegundoApellido());
                datosUsuario.setCargo(certificadoFuncionarioPublico.getCargo());
                datosUsuario.setInstitucion(certificadoFuncionarioPublico.getInstitucion());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoAnfAc37442 instanceof CertificadoPersonaJuridica) {
                CertificadoPersonaJuridica certificadoPersonaJuridica = (CertificadoPersonaJuridica) certificadoAnfAc37442;
                datosUsuario.setCedula(certificadoPersonaJuridica.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaJuridica.getNombres());
                datosUsuario.setApellido(certificadoPersonaJuridica.getPrimerApellido() + " "
                        + certificadoPersonaJuridica.getSegundoApellido());
                datosUsuario.setCargo(certificadoPersonaJuridica.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }

            if (certificadoAnfAc37442 instanceof CertificadoPersonaNatural) {
                CertificadoPersonaNatural certificadoPersonaNatural = (CertificadoPersonaNatural) certificadoAnfAc37442;
                datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                        + certificadoPersonaNatural.getSegundoApellido());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoAnfAc37442 instanceof CertificadoSelladoTiempo) {
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            datosUsuario.setEntidadCertificadora("Anf AC");
            datosUsuario.setCertificadoDigitalValido(true);
            return datosUsuario;
        }
        if (CertificadoDigercicFactory.esCertificadoDigercic(certificado)) {
            CertificadoDigercic certificadoDigercic = CertificadoDigercicFactory.construir(certificado);
            if (certificadoDigercic instanceof CertificadoPersonaNatural) {
                CertificadoPersonaNatural certificadoPersonaNatural = (CertificadoPersonaNatural) certificadoDigercic;

                datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                datosUsuario.setNombre(Utils.getCN(certificado));
                datosUsuario.setApellido("");
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            datosUsuario.setEntidadCertificadora("DIGERCIC");
            datosUsuario.setCertificadoDigitalValido(true);
            return datosUsuario;
        }
        if (CertificadoUanatacaDataFactory.esCertificadoUanataca(certificado)) {
            CertificadoUanataca certificadoUanataca = CertificadoUanatacaDataFactory.construir(certificado);
            if (certificadoUanataca instanceof CertificadoMiembroEmpresaUanataca) {
                CertificadoMiembroEmpresaUanataca certificadoMiembroEmpresaUanataca = (CertificadoMiembroEmpresaUanataca) certificadoUanataca;
                datosUsuario.setCedula(certificadoMiembroEmpresaUanataca.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoMiembroEmpresaUanataca.getNombres());
                datosUsuario.setApellido(certificadoMiembroEmpresaUanataca.getPrimerApellido() + " "
                        + certificadoMiembroEmpresaUanataca.getSegundoApellido());
                datosUsuario.setCargo(certificadoMiembroEmpresaUanataca.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            } else if (certificadoUanataca instanceof CertificadoPersonaJuridicaPrivadaUanataca) {
                CertificadoPersonaJuridicaPrivadaUanataca certificadoPersonaJuridicaUanataca = (CertificadoPersonaJuridicaPrivadaUanataca) certificadoUanataca;
                datosUsuario.setCedula(certificadoPersonaJuridicaUanataca.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaJuridicaUanataca.getNombres());
                datosUsuario.setApellido(certificadoPersonaJuridicaUanataca.getPrimerApellido() + " "
                        + certificadoPersonaJuridicaUanataca.getSegundoApellido());
                datosUsuario.setCargo(datosUsuario.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            } else if (certificadoUanataca instanceof CertificadoPersonaNaturalUanataca) {
                CertificadoPersonaNaturalUanataca certificadoPersonaNaturalU = (CertificadoPersonaNaturalUanataca) certificadoUanataca;
                datosUsuario.setCedula(certificadoPersonaNaturalU.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaNaturalU.getNombres());
                datosUsuario.setApellido(certificadoPersonaNaturalU.getPrimerApellido() + " "
                        + certificadoPersonaNaturalU.getSegundoApellido());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            } else if (certificadoUanataca instanceof CertificadoRepresentanteLegalUanataca) {
                CertificadoRepresentanteLegalUanataca certificadoRepresentanteLegalUanataca = (CertificadoRepresentanteLegalUanataca) certificadoUanataca;
                datosUsuario.setCedula(certificadoRepresentanteLegalUanataca.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoRepresentanteLegalUanataca.getNombres());
                datosUsuario.setApellido(certificadoRepresentanteLegalUanataca.getPrimerApellido() + " "
                        + certificadoRepresentanteLegalUanataca.getSegundoApellido());
                datosUsuario.setCargo(certificadoRepresentanteLegalUanataca.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            } else if (certificadoUanataca instanceof CertificadoSelladoTiempo) {
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
                datosUsuario.setSelladoTiempo(true);
            }
            datosUsuario.setEntidadCertificadora("Uanataca Ecuador");
            datosUsuario.setCertificadoDigitalValido(true);
            return datosUsuario;
        }
        if (CertificadoEclipsoftDataFactory.esCertificadoEclipsoft(certificado)) {
            CertificadoEclipsoft certificadoEclipsoft = CertificadoEclipsoftDataFactory.construir(certificado);
            if (certificadoEclipsoft instanceof CertificadoPersonalNaturalEclipsoft) {
                CertificadoPersonalNaturalEclipsoft certificadoPersonalNaturalEclipsoft = (CertificadoPersonalNaturalEclipsoft) certificadoEclipsoft;
                datosUsuario.setCedula(certificadoPersonalNaturalEclipsoft.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonalNaturalEclipsoft.getNombres());
                datosUsuario.setApellido(certificadoPersonalNaturalEclipsoft.getPrimerApellido() + " " + certificadoPersonalNaturalEclipsoft.getSegundoApellido());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            } else if (certificadoEclipsoft instanceof CertificadoMiembroEmpresaEclipsoft) {
                CertificadoMiembroEmpresaEclipsoft certificadoMiembroEmpresaEclipsoft = (CertificadoMiembroEmpresaEclipsoft) certificadoEclipsoft;
                datosUsuario.setCedula(certificadoMiembroEmpresaEclipsoft.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoMiembroEmpresaEclipsoft.getNombres());
                datosUsuario.setApellido(certificadoMiembroEmpresaEclipsoft.getPrimerApellido() + " " + certificadoMiembroEmpresaEclipsoft.getSegundoApellido());
                datosUsuario.setCargo(certificadoMiembroEmpresaEclipsoft.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            } else if (certificadoEclipsoft instanceof CertificadoRepresentanteLegalEclipsoft) {
                CertificadoRepresentanteLegalEclipsoft certificadoRepresentanteLegalEclipsoft = (CertificadoRepresentanteLegalEclipsoft) certificadoEclipsoft;
                datosUsuario.setCedula(certificadoRepresentanteLegalEclipsoft.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoRepresentanteLegalEclipsoft.getNombres());
                datosUsuario.setApellido(certificadoRepresentanteLegalEclipsoft.getPrimerApellido() + " " + certificadoRepresentanteLegalEclipsoft.getSegundoApellido());
                datosUsuario.setCargo(certificadoRepresentanteLegalEclipsoft.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            } else if (certificadoEclipsoft instanceof CertificadoPersonaJuridicaPrivadaEclipsoft) {
                CertificadoPersonaJuridicaPrivadaEclipsoft certificadoPersonaJuridicaPrivadaEclipsoft = (CertificadoPersonaJuridicaPrivadaEclipsoft) certificadoEclipsoft;
                datosUsuario.setCedula(certificadoPersonaJuridicaPrivadaEclipsoft.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaJuridicaPrivadaEclipsoft.getNombres());
                datosUsuario.setApellido(certificadoPersonaJuridicaPrivadaEclipsoft.getPrimerApellido() + " " + certificadoPersonaJuridicaPrivadaEclipsoft.getSegundoApellido());
                datosUsuario.setCargo(datosUsuario.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            } else if (certificadoEclipsoft instanceof CertificadoSelladoTiempo) {
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            datosUsuario.setEntidadCertificadora(ECLIPSOFT_NAME);
            datosUsuario.setCertificadoDigitalValido(true);
            return datosUsuario;
        }
        if (CertificadoDatilDataFactory.esCertificadoDatil(certificado)) {
            CertificadoDatil certificadoDatil = CertificadoDatilDataFactory.construir(certificado);
            if (certificadoDatil instanceof CertificadoMiembroEmpresaDatil) {
                CertificadoMiembroEmpresaDatil certificadoMiembroEmpresaDatil = (CertificadoMiembroEmpresaDatil) certificadoDatil;
                datosUsuario.setCedula(certificadoMiembroEmpresaDatil.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoMiembroEmpresaDatil.getNombres());
                datosUsuario.setApellido(certificadoMiembroEmpresaDatil.getPrimerApellido() + " " + certificadoMiembroEmpresaDatil.getSegundoApellido());
                datosUsuario.setCargo(certificadoMiembroEmpresaDatil.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoDatil instanceof CertificadoPersonaJuridicaPrivadaDatil) {
                CertificadoPersonaJuridicaPrivadaDatil certificadoPersonaJuridicaPrivadaDatil = (CertificadoPersonaJuridicaPrivadaDatil) certificadoDatil;
                datosUsuario.setCedula(certificadoPersonaJuridicaPrivadaDatil.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaJuridicaPrivadaDatil.getNombres());
                datosUsuario.setApellido(certificadoPersonaJuridicaPrivadaDatil.getPrimerApellido() + " "
                        + certificadoPersonaJuridicaPrivadaDatil.getSegundoApellido());
                datosUsuario.setCargo(certificadoPersonaJuridicaPrivadaDatil.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoDatil instanceof CertificadoRepresentanteLegalDatil) {
                CertificadoRepresentanteLegalDatil certificadoRepresentanteLegalDatil = (CertificadoRepresentanteLegalDatil) certificadoDatil;
                datosUsuario.setCedula(certificadoRepresentanteLegalDatil.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoRepresentanteLegalDatil.getNombres());
                datosUsuario.setApellido(certificadoRepresentanteLegalDatil.getPrimerApellido() + " "
                        + certificadoRepresentanteLegalDatil.getSegundoApellido());
                datosUsuario.setCargo(certificadoRepresentanteLegalDatil.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoDatil instanceof CertificadoPersonaNaturalDatil) {
                CertificadoPersonaNaturalDatil certificadoPersonaNaturalDatil = (CertificadoPersonaNaturalDatil) certificadoDatil;
                datosUsuario.setCedula(certificadoPersonaNaturalDatil.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaNaturalDatil.getNombres());
                datosUsuario.setApellido(certificadoPersonaNaturalDatil.getPrimerApellido() + " "
                        + certificadoPersonaNaturalDatil.getSegundoApellido());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoDatil instanceof CertificadoSelladoTiempo) {
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            datosUsuario.setEntidadCertificadora(DATIL_NAME);
            datosUsuario.setCertificadoDigitalValido(true);
            return datosUsuario;
        }
        if (CertificadoArgosDataFactory.esCertificadoArgosData(certificado)) {
            CertificadoArgosData certificadoArgosData = CertificadoArgosDataFactory.construir(certificado);
            if (certificadoArgosData instanceof CertificadoPersonaNaturalArgosData) {
                CertificadoPersonaNaturalArgosData certificadoPersonaNatural = (CertificadoPersonaNaturalArgosData) certificadoArgosData;
                datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoPersonaNatural.getNombres());
                datosUsuario.setApellido(certificadoPersonaNatural.getPrimerApellido() + " "
                        + certificadoPersonaNatural.getSegundoApellido());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            } else if (certificadoArgosData instanceof CertificadoRepresentanteLegalArgosData) {
                CertificadoRepresentanteLegalArgosData certificadoRepresentanteLegal = (CertificadoRepresentanteLegalArgosData) certificadoArgosData;
                datosUsuario.setCedula(certificadoRepresentanteLegal.getCedulaPasaporte());
                datosUsuario.setNombre(certificadoRepresentanteLegal.getNombres());
                datosUsuario.setApellido(certificadoRepresentanteLegal.getPrimerApellido() + " "
                        + certificadoRepresentanteLegal.getSegundoApellido());
                datosUsuario.setCargo(certificadoRepresentanteLegal.getCargo());
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            datosUsuario.setEntidadCertificadora(AGOSDATA_NAME);
            datosUsuario.setCertificadoDigitalValido(true);
            return datosUsuario;
        }
        
        if (CertificadoLazzateDataFactory.esCertificadoLazzate(certificado)) {
            CertificadoLazzate certificadoLazzate = CertificadoLazzateDataFactory.construir(certificado);
            if (certificadoLazzate instanceof CertificadoPersonaNatural) {
                CertificadoPersonaNatural certificadoPersonaNatural = (CertificadoPersonaNatural) certificadoLazzate;

                datosUsuario.setCedula(certificadoPersonaNatural.getCedulaPasaporte());
                datosUsuario.setNombre(Utils.getCN(certificado));
                datosUsuario.setApellido("");
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            if (certificadoLazzate instanceof CertificadoPersonaJuridica) {
                CertificadoPersonaJuridica certificadoPersonaJuridica= (CertificadoPersonaJuridica) certificadoLazzate;

                datosUsuario.setCedula(certificadoPersonaJuridica.getCedulaPasaporte());
                datosUsuario.setInstitucion(certificadoPersonaJuridica.getRazonSocial());
                datosUsuario.setCargo(certificadoPersonaJuridica.getCargo());
                datosUsuario.setNombre(Utils.getCN(certificado));
                datosUsuario.setApellido("");
                datosUsuario.setSerial(certificado.getSerialNumber().toString());
            }
            datosUsuario.setEntidadCertificadora(LAZZATE_NAME);
            datosUsuario.setCertificadoDigitalValido(true);
            return datosUsuario;
        }
        return null;
    }
}
