package ec.gob.firmadigital.pdf;

import ec.gob.firmadigital.model.Document;

public interface PdfSignature {

	Document sign(final Document pdfData, final byte[] signatureValue, final SignatureParameters parameters);
}
