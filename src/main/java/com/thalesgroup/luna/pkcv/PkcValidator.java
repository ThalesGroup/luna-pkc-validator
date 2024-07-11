/****************************************************************************\
*
* This file is provided under the MIT license (see the following Web site
* for further details: https://mit-license.org/ ).
*
* Copyright © 2024 Thales Group
*
\****************************************************************************/

package com.thalesgroup.luna.pkcv;

import java.security.cert.Certificate;
import java.util.List;

public final class PkcValidator {
	private Certificate leaf;
	private Certificate root;

	PkcValidator() {
	}

	public Certificate getRoot() {
		return root;
	}

	public Certificate getLeaf() {
		return leaf;
	}

	/**
	 * Validate a certificate chain path from the leaf to the root.
	 *
	 * @param certificates List of certificates
	 *
	 * @return <code>true</code> if the certificate chain is valid
	 *         <code>false</code> otherwise.
	 */
	public boolean validateCertificateChain(final List<? extends Certificate> certificates) {
		return validateCertificateChain(certificates, false);
	}

	/**
	 * Validate a certificate chain path from the leaf to the root.
	 *
	 * @param certificates List of certificates
	 * @param quiet        flag indicating do not print certificates
	 *
	 * @return <code>true</code> if the certificate chain is valid
	 *         <code>false</code> otherwise.
	 */
	public boolean validateCertificateChain(final List<? extends Certificate> certificates, boolean quiet) {
		for (int i = 0; i < certificates.size(); i++) {
			if (!quiet) {
				System.out.println("Certificate:" + i);
				System.out.println(certificates.get(i));
			}

			try {
				if (i == 0) {
					// Leaf certiticate.
					leaf = certificates.get(i);
					certificates.get(i).verify(certificates.get(i + 1).getPublicKey());
				} else if (i == certificates.size() - 1) { // root
					if (isSelfSigned(certificates.get(i))) {
						root = certificates.get(i);
						certificates.get(i).verify(certificates.get(i).getPublicKey());
					} else {
						// Root must be self signed.
						return false;
					}
				} else {
					// Intermediate certificate.
					certificates.get(i).verify(certificates.get(i + 1).getPublicKey());
				}
			} catch (Exception e) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Determine if the given certificate is self signed.
	 *
	 * @param certificate Certificate to be verified as self-signed against its own
	 *                    public key.
	 *
	 * @return <code>true</code> if the certificate is self signed
	 *         <code>false</code> otherwise, in the case of any exception.
	 */
	private static boolean isSelfSigned(final Certificate certificate) {
		try {
			certificate.verify(certificate.getPublicKey());

			return true;
		} catch (Exception e) {
			return false;
		}
	}
}
