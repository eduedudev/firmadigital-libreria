package ec.gob.firmadigital.pades.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Collections;

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.CrlClientOnline;
import com.itextpdf.signatures.ICrlClient;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.IOcspClient;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.OCSPVerifier;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.TSAClientBouncyCastle;

import ec.gob.firmadigital.model.Document;
import ec.gob.firmadigital.model.InMemoryDocument;
import ec.gob.firmadigital.model.RubricaRuntimeException;
import ec.gob.firmadigital.pades.SignatureParameters;
import ec.gob.firmadigital.sign.RubricaSigner;
import ec.gob.firmadigital.sign.pdf.itext.ITextSignerAdapter;

public class BasicSignature {

    private RubricaSigner rubricaSigner;

    public BasicSignature(RubricaSigner rubricaSigner) {
        this.rubricaSigner = rubricaSigner;
    }

    public Document sign(Document document, SignatureParameters parameters) {
        try (PdfReader reader = new PdfReader(document.openStream());
                ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            StampingProperties properties = new StampingProperties();
            properties.useAppendMode();

            PdfSigner signer = new PdfSigner(reader, os, properties);
            IExternalDigest digest = new BouncyCastleDigest();
            IExternalSignature signature = new ITextSignerAdapter(rubricaSigner);
            Certificate[] chain = parameters.getChain();

            ICrlClient crlClient = new CrlClientOnline();
            OCSPVerifier ocspVerifier = new OCSPVerifier(null, null);
            IOcspClient ocspClient = new OcspClientBouncyCastle(ocspVerifier);

            ITSAClient tsc = new TSAClientBouncyCastle(parameters.getTsaUrl(), parameters.getTsaUsername(),
                    parameters.getTsaPassword());

            Collection<ICrlClient> crlClients = Collections.singleton(crlClient);

            signer.signDetached(digest, signature, chain, crlClients, ocspClient, tsc, 0,
                    PdfSigner.CryptoStandard.CADES);

            return new InMemoryDocument(os.toByteArray());
        } catch (IOException e) {
            throw new RubricaRuntimeException(e);
        } catch (GeneralSecurityException e) {
            throw new RubricaRuntimeException(e);
        }
    }

    private String getTsalUrl() {
        return null;
    }
}
