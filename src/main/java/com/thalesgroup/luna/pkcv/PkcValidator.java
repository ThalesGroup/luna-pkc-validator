/****************************************************************************\
*
* This file is provided under the MIT license (see the following Web site
* for further details: https://mit-license.org/ ).
*
* Copyright © 2024 Thales Group
*
\****************************************************************************/

package com.thalesgroup.luna.pkcv;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import sun.security.util.DerInputStream;

@SuppressWarnings("restriction")
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

	/**
	 * Validate the Extended Key Usage for the PKC Chain.
	 * 
	 * @param pkc        chain ,
	 * @param extensions of Luna Certificate chain
	 * 
	 * @return <code>true</code> if the pkc match the Luna extensions
	 *         <code>false</code> if the pkc chain does not match the Luna
	 *         extensions .
	 * 
	 */

	public boolean validatePKCExtensions(final List<X509Certificate> certificates, String[] eku) {

		for (int i = 0; i < certificates.size(); i++) {

			try {
				List<String> extendedKeyUsage = certificates.get(i).getExtendedKeyUsage();

				if (extendedKeyUsage != null) {

					for (String usage : extendedKeyUsage) {
						if (usage.equals(eku[i]) == false) {
							return false;
						}

					}

				}

			} catch (CertificateParsingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

		}

		return true;
	}

	/**
	 * Determine the serial number from pkc chain .
	 *
	 * @param leaf certificate from pkc chain chain.
	 *
	 * @return <code>true</code> if the version is available
	 *         <code>false</code> otherwise, in the case of any exception.
	 */

	// @SuppressWarnings("restriction")
	public boolean printSerialNumberofHSM(X509Certificate cert) {
		byte[] extVal = cert.getExtensionValue("1.3.6.1.4.1.12383.2.1");
		if (extVal != null) {
			try {
				// Strip the OCTET STRING wrapper
				DerInputStream derIn = new DerInputStream(extVal);
				byte[] extValue = derIn.getOctetString();
				ByteBuffer bb = ByteBuffer.allocate(extValue.length);
				bb.order(ByteOrder.LITTLE_ENDIAN);
				bb.put(extValue);
				bb.position(0);
				System.out.println("PKC from HSM Serail number: " + bb.getInt());
				return true;

			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			return false;
		}
		return false;

	}

	/**
	 * Determine the firmware version from pkc chain .
	 *
	 * @param leaf certificate from pkc chain chain.
	 *
	 * @return <code>true</code> if the version is available
	 *         <code>false</code> otherwise, in the case of any exception.
	 *         printFirmwareVersion
	 */

	public static boolean printFirmwareVersion(X509Certificate cert) {
		byte[] extVal = cert.getExtensionValue("1.3.6.1.4.1.12383.2.3");
		if (extVal != null) {
			try {
				// Strip the OCTET STRING wrapper
				DerInputStream derIn = new DerInputStream(extVal);
				byte[] extValue = derIn.getOctetString();

				ByteBuffer bb = ByteBuffer.allocate(2);
				bb.order(ByteOrder.LITTLE_ENDIAN);
				bb.put(Arrays.copyOfRange(extValue, 2, 3));
				bb.position(0);
				System.out.print("Firmware Version of the HSM " + bb.getShort());
				bb.position(0);
				bb.put(Arrays.copyOfRange(extValue, 0, 1));
				bb.position(0);
				System.out.println(bb.getShort());
				return true;

			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			return false;
		}
		return false;

	}

}
