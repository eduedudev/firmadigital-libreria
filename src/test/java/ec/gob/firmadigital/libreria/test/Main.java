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
package ec.gob.firmadigital.libreria.test;

import static ec.gob.firmadigital.libreria.certificate.CertUtils.seleccionarAlias;
import static ec.gob.firmadigital.libreria.utils.Utils.dateToCalendar;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;
import java.util.Date;
import java.util.Properties;
import ec.gob.firmadigital.libreria.certificate.CertEcUtils;
import ec.gob.firmadigital.libreria.certificate.to.Certificado;
import ec.gob.firmadigital.libreria.certificate.to.DatosUsuario;
import ec.gob.firmadigital.libreria.certificate.to.Documento;
import ec.gob.firmadigital.libreria.core.Util;
import ec.gob.firmadigital.libreria.exceptions.HoraServidorException;
import ec.gob.firmadigital.libreria.exceptions.InvalidFormatException;
import ec.gob.firmadigital.libreria.exceptions.SignatureVerificationException;
import ec.gob.firmadigital.libreria.keystore.FileKeyStoreProvider;
import ec.gob.firmadigital.libreria.keystore.KeyStoreProvider;
import ec.gob.firmadigital.libreria.keystore.KeyStoreProviderFactory;
import ec.gob.firmadigital.libreria.model.Document;
import ec.gob.firmadigital.libreria.model.InMemoryDocument;
import ec.gob.firmadigital.libreria.sign.DigestAlgorithm;
import ec.gob.firmadigital.libreria.sign.PrivateKeySigner;
import ec.gob.firmadigital.libreria.sign.SignConstants;
import ec.gob.firmadigital.libreria.sign.pdf.BasePdfSigner;
import ec.gob.firmadigital.libreria.sign.pdf.RectanguloUtil;
import ec.gob.firmadigital.libreria.sign.xades.XAdESSigner;
import ec.gob.firmadigital.libreria.utils.FileUtils;
import ec.gob.firmadigital.libreria.utils.Json;
import ec.gob.firmadigital.libreria.utils.PropertiesUtils;
import ec.gob.firmadigital.libreria.utils.TiempoUtils;
import ec.gob.firmadigital.libreria.utils.Utils;
import ec.gob.firmadigital.libreria.utils.UtilsCrlOcsp;
import ec.gob.firmadigital.libreria.utils.X509CertificateUtils;
import ec.gob.firmadigital.libreria.validaciones.DocumentoUtils;
import java.io.InputStream;

/**
 * Metodo de pruebas funcionales
 *
 * @author mfernandez
 */
public class Main {

    // ARCHIVO
    private static final String PKCS12 = "/home/mfernandez/appFirmaEC/pruebaPre2024.p12";
    private static final String PASSWORD = "123456";
    private static final String FILE = "/home/mfernandez/Descargas/Manual Usuario FirmaEC v3.pdf";
    private static final String ALGORITHM = "SHA512";

    public static void main(String args[]) throws KeyStoreException, Exception {
//        firmarPades(FILE);
//        firmarDocumentoXML(FILE);
//        validarCertificado();
        verificarDocumento(FILE);
    }

    private static void firmarPades(String file) throws KeyStoreException, Exception {
        KeyStore keyStore = getKeyStore(PKCS12, PASSWORD, null);
//        KeyStore keyStore = getKeyStore(null, PASSWORD, "TOKEN");"TOKEN", "PCSC"
        ////// LEER PDF:
        byte[] docByteArry = DocumentoUtils.loadFile(file);

        byte[] signed = null;
        String alias = seleccionarAlias(keyStore, null);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, PASSWORD.toCharArray());
        Certificate[] certChain = keyStore.getCertificateChain(alias);
        //////////////////////////////////////////////////////
        Document document = new InMemoryDocument(docByteArry);
        try (InputStream is = document.openStream()) {
            // Configurar el PdfSigner
            Properties properties = parametros();
            // Crear un RubricaSigner para firmar el MessageDigest del documento
            PrivateKeySigner signer = new PrivateKeySigner(privateKey, DigestAlgorithm.forName(ALGORITHM));
            // Crear un PdfSigner para firmar el documento
//            ec.gob.firmadigital.libreria.sign.pdf.PadesBasicSigner pdfSigner = new ec.gob.firmadigital.libreria.sign.pdf.PadesBasicSigner(signer);
            ec.gob.firmadigital.libreria.sign.pdf.PadesEnhancedSigner pdfSigner = new ec.gob.firmadigital.libreria.sign.pdf.PadesEnhancedSigner(signer);
//            ec.gob.firmadigital.libreria.sign.pdf.PadesLtvSigner pdfSigner = new ec.gob.firmadigital.libreria.sign.pdf.PadesLtvSigner(signer);
            signed = pdfSigner.sign(is, privateKey, certChain, properties);
        }
        //////////////////////////////////////////////////////
        System.out.println("final firma\n-------");
        ////// Permite guardar el archivo en el equipo y luego lo abre
        String nombreDocumento = FileUtils.crearNombreFirmado(new File(file), FileUtils.getExtension(signed));
        FileOutputStream fos = new java.io.FileOutputStream(nombreDocumento);
        fos.write(signed);
        fos.close();
        abrirDocumento(nombreDocumento);
    }

    private static void firmarDocumentoXML(String file) throws KeyStoreException, Exception {
        KeyStore keyStore = getKeyStore(PKCS12, PASSWORD, null);
//        KeyStore keyStore = getKeyStore(null, PASSWORD, "TOKEN");"TOKEN", "PCSC"
        ////// LEER XML:
        byte[] docByteArry = DocumentoUtils.loadFile(file);

        byte[] signed = null;
        String alias = seleccionarAlias(keyStore, null);
        PrivateKey key = (PrivateKey) keyStore.getKey(alias, PASSWORD.toCharArray());

        X509CertificateUtils x509CertificateUtils = new X509CertificateUtils();
        try {
            if (x509CertificateUtils.validarX509Certificate((X509Certificate) keyStore.getCertificate(alias), null, PropertiesUtils.versionBase64())) {//validación de firmaEC
                Certificate[] certChain = keyStore.getCertificateChain(alias);
                XAdESSigner signer = new XAdESSigner();
                signed = signer.sign(docByteArry, SignConstants.SIGN_ALGORITHM_SHA512WITHRSA, key, certChain, null, PropertiesUtils.versionBase64());
                System.out.println("final firma\n-------");
                ////// Permite guardar el archivo en el equipo y luego lo abre
                String nombreDocumento = FileUtils.crearNombreFirmado(new File(file), FileUtils.getExtension(signed));
                FileOutputStream fos = new java.io.FileOutputStream(nombreDocumento);
                fos.write(signed);
                fos.close();
                abrirDocumento(nombreDocumento);
            } else {
                System.out.println("Entidad Certificadora no reconocida");
            }
        } catch (Exception e) {
            if (e.getClass() == IllegalArgumentException.class) {
                System.out.println("Problemas con la emisión del certificado digital");
            } else {
                e.printStackTrace();
            }
        }
    }

    private static void validarCertificado() throws KeyStoreException, Exception {
        KeyStore keyStore = getKeyStore(PKCS12, PASSWORD, null);//ARCHIVO
//        KeyStore keyStore = getKeyStore(null, PASSWORD, "TOKEN");//"TOKEN", "PCSC"
        String alias = seleccionarAlias(keyStore, null);
        X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate(alias);
        System.out.println("x509Certificate.getSerialNumber(): " + x509Certificate.getSerialNumber());
        UtilsCrlOcsp.validarOCSP(x509Certificate);
        System.out.println("UID: " + Utils.getUID(x509Certificate));
        System.out.println("CN: " + Utils.getCN(x509Certificate));
        System.out.println("emisión: " + CertEcUtils.getNombreCA(x509Certificate));
        System.out.println("fecha emisión: " + x509Certificate.getNotBefore());
        System.out.println("fecha expiración: " + x509Certificate.getNotAfter());
        System.out.println("ISSUER: " + x509Certificate.getIssuerX500Principal().getName());
        System.out.println("Subject: " + x509Certificate.getSubjectDN());
        System.out.println("Serial: " + x509Certificate.getSerialNumber());

        Date fechaHoraISO = fechaHoraISO();
        //Validad certificado revocado
        Date fechaRevocado = UtilsCrlOcsp.validarFechaRevocado(x509Certificate, null);
        //Desarrollo
//        Date fechaRevocado = UtilsCrlOcsp.validarOCSPDate(x509Certificate);
        if (fechaRevocado != null && fechaRevocado.compareTo(fechaHoraISO) <= 0) {
            System.out.println("Certificado revocado: " + fechaRevocado);
        }
        if (fechaHoraISO.compareTo(x509Certificate.getNotBefore()) <= 0 || fechaHoraISO.compareTo(x509Certificate.getNotAfter()) >= 0) {
            System.out.println("Certificado expirado");
        }
        System.out.println("Certificado emitido por entidad certificadora acreditada? " + Utils.verifySignature(x509Certificate));

        DatosUsuario datosUsuario = CertEcUtils.getDatosUsuarios(x509Certificate);
        Certificado certificado = new Certificado(
                x509Certificate.getSerialNumber().toString(),
                Util.getCN(x509Certificate),
                CertEcUtils.getNombreCA(x509Certificate),
                dateToCalendar(x509Certificate.getNotBefore()),
                dateToCalendar(x509Certificate.getNotAfter()),
                null,
                dateToCalendar(UtilsCrlOcsp.validarFechaRevocado(x509Certificate, null)),
                null,
                datosUsuario);
        certificado.setKeyUsages(Utils.validacionKeyUsages(x509Certificate));

        System.out.println("Certificado: " + certificado);
        System.out.println(Json.generarJsonCertificado(certificado));
    }

    private static void verificarDocumento(String file) throws IOException, SignatureVerificationException, Exception {
        File document = new File(file);
        Documento documento = Utils.verificarDocumento(document, PropertiesUtils.versionBase64());
        System.out.println("JSON:");
        System.out.println(Json.generarJsonDocumento(documento));
        System.out.println("Documento: " + documento);
        if (documento.getCertificados() != null) {
            documento.getCertificados().forEach((certificado) -> {
                System.out.println(certificado.toString());
            });
        } else {
            throw new InvalidFormatException("Documento no soportado");
        }
    }

    private static Properties parametros() throws IOException, HoraServidorException {
        //PageSize.A4.getWidth();//595.0
        //PageSize.A4.getHeight();//842.0
        //QR
        //SUPERIOR IZQUIERDA
        String llx = "10";
        String lly = "830";
        //SUPERIOR CENTRO
        //String llx = "250";
        //String lly = "510";
        //INFERIOR IZQUIERDA
        //String llx = "100";
        //String lly = "91";
        //INFERIOR DERECHA
        //String llx = "419";
        //String lly = "91";
        //INFERIOR CENTRADO
        //String llx = "260";
        //String lly = "91";
        //QR
        //SUPERIOR IZQUIERDA
        //String llx = "10";
        //String lly = "830";
        //String urx = String.valueOf(Integer.parseInt(llx) + 110);
        //String ury = String.valueOf(Integer.parseInt(lly) - 36);
        //INFERIOR CENTRADO
        //String llx = "190";
        //String lly = "85";
        //String urx = String.valueOf(Integer.parseInt(llx) + 260);
        //String ury = String.valueOf(Integer.parseInt(lly) - 36);
        //INFERIOR CENTRADO (ancho pie pagina)
        //String llx = "100";
        //String lly = "85";
        //String urx = String.valueOf(Integer.parseInt(llx) + 430);
        //String ury = String.valueOf(Integer.parseInt(lly) - 25);
        //INFERIOR DERECHA
        //String llx = "10";
        //String lly = "85";
        //String urx = String.valueOf(Integer.parseInt(llx) + 260);
        //String ury = String.valueOf(Integer.parseInt(lly) - 36);

        Properties params = new Properties();
        params.setProperty(BasePdfSigner.SIGNING_LOCATION, "Teletrabajo");
        params.setProperty(BasePdfSigner.SIGNING_REASON, "Firmado digitalmente con RUBRICA");
        params.setProperty(BasePdfSigner.SIGN_TIME, TiempoUtils.getFechaHoraServidor(null, PropertiesUtils.versionBase64()));
        params.setProperty(BasePdfSigner.LAST_PAGE, "6");
        params.setProperty(BasePdfSigner.TYPE_SIG, "QR");
        params.setProperty(BasePdfSigner.INFO_QR, "Firmado digitalmente con RUBRICA\nhttps://minka.gob.ec/rubrica/rubrica");
        //params.setProperty(BasePdfSigner.TYPE_SIG, "information2");
        //params.setProperty(BasePdfSigner.FONT_SIZE, "4.5");
        // Posicion firma
        params.setProperty(RectanguloUtil.POSITION_ON_PAGE_LOWER_LEFT_X, llx);
        params.setProperty(RectanguloUtil.POSITION_ON_PAGE_LOWER_LEFT_Y, lly);
        //params.setProperty(RectanguloUtil.POSITION_ON_PAGE_UPPER_RIGHT_X, urx);
        //params.setProperty(RectanguloUtil.POSITION_ON_PAGE_UPPER_RIGHT_Y, ury);
        return params;
    }

    private static KeyStore getKeyStore(String archivo, String password, String tipoKeyStoreProvider) throws KeyStoreException {
        if (archivo != null) { // ARCHIVO
            KeyStoreProvider ksp = new FileKeyStoreProvider(archivo);
            return ksp.getKeystore(password.toCharArray());
        } else { // TOKEN
            return KeyStoreProviderFactory.getKeyStore(password, tipoKeyStoreProvider);
        }
    }

    private static Date fechaHoraISO() throws IOException, HoraServidorException {
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
        TemporalAccessor accessor = dateTimeFormatter.parse(TiempoUtils.getFechaHoraServidor(null, PropertiesUtils.versionBase64()));
        return Date.from(Instant.from(accessor));
    }
    
    private static void abrirDocumento(String nombreDocumento) throws IOException, KeyStoreException, Exception {
        //Abrir documento
        new java.util.Timer().schedule(new java.util.TimerTask() {
            @Override
            public void run() {
                try {
                    FileUtils.abrirDocumento(nombreDocumento);
                    System.out.println(nombreDocumento);
                    // verificarDocumento(nombreDocumento);
                } catch (IOException ex) {
                    ex.printStackTrace();
                } finally {
                    System.exit(0);
                }
            }
        }, 1000); //espera 1 segundo
    }
}
