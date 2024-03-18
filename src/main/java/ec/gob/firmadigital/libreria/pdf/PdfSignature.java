package ec.gob.firmadigital.libreria.pdf;

import ec.gob.firmadigital.libreria.model.Document;

public interface PdfSignature {

	Document sign(final Document pdfData, final byte[] signatureValue, final SignatureParameters parameters);
}
