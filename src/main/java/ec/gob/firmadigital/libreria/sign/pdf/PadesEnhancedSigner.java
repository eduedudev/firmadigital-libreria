/*
 * Copyright (C) 2021 
 * Authors: Ricardo Arguello
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
package ec.gob.firmadigital.libreria.sign.pdf;

import com.itextpdf.signatures.BouncyCastleDigest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.Properties;
import java.util.logging.Logger;

import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.TSAClientBouncyCastle;

import ec.gob.firmadigital.libreria.sign.RubricaSigner;
import ec.gob.firmadigital.libreria.sign.pdf.itext.SignerAdapter;
import ec.gob.firmadigital.libreria.utils.BouncyCastleUtils;
import ec.gob.firmadigital.libreria.utils.PropertiesUtils;
import java.io.InputStream;
import java.security.PrivateKey;
import java.util.logging.Level;

/**
 * PAdES Enhanced - PAdES-BES
 */
public class PadesEnhancedSigner extends BasePdfSigner {

    private final IExternalSignature externalSignature;

    private static final Logger LOGGER = Logger.getLogger(PadesEnhancedSigner.class.getName());

    public PadesEnhancedSigner(RubricaSigner signer) {
        this.externalSignature = new SignerAdapter(signer);
    }

    public byte[] sign(InputStream inputStream, PrivateKey privateKey, Certificate[] certificates, Properties properties) throws IOException {
        BouncyCastleUtils.initializeBouncyCastle();
        try {
            // Firmar el documento
            byte[] hash = emptySignature(inputStream, certificates, properties, externalSignature.getDigestAlgorithmName());
            String fieldName = getFieldName();
            ByteArrayOutputStream documentoPorFirmar = getDocumentoPorFirmar();
            byte[] hashSigned = this.signed_hash(hash, privateKey, certificates, properties.getProperty("identificacion"));
            createSignature(hashSigned, documentoPorFirmar, fieldName, privateKey, certificates);
            return getDocumentoFirmado().toByteArray();
        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Error al firmar: {0}", e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private byte[] signed_hash(byte[] hash, PrivateKey pk, Certificate[] chain, String identificacion) throws GeneralSecurityException {
        PrivateKeySignature signature = new PrivateKeySignature(pk, externalSignature.getDigestAlgorithmName(), null);
        BouncyCastleDigest digest = new BouncyCastleDigest();
        PdfPKCS7 sgn = new PdfPKCS7(null, chain, externalSignature.getDigestAlgorithmName(), null, digest, false);
        byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, com.itextpdf.signatures.PdfSigner.CryptoStandard.CMS, null, null);
        byte[] extSignature = signature.sign(sh);
        sgn.setExternalSignatureValue(extSignature, null, signature.getSignatureAlgorithmName());
        ITSAClient tsaClient = null;
        if (identificacion != null && !identificacion.isEmpty()) {
            tsaClient = new TSAClientBouncyCastle(PropertiesUtils.getConfig().getProperty("tsa_url"), identificacion, identificacion);
        }

        return sgn.getEncodedPKCS7(hash, com.itextpdf.signatures.PdfSigner.CryptoStandard.CMS, tsaClient, null, null);
    }
}
