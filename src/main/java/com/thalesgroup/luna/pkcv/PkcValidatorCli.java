/****************************************************************************\
*
* This file is provided under the MIT license (see the following Web site
* for further details: https://mit-license.org/ ).
*
* Copyright © 2024 Thales Group
*
\****************************************************************************/

package com.thalesgroup.luna.pkcv;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.List;

import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemReader;

public class PkcValidatorCli {
	static Certificate leaf;
	static Certificate root;

	static void usage(int code) {
		PrintStream outputStream = System.err;

		if (code == 0) {
			outputStream = System.out;
		}

		outputStream.println("java -jar luna-pkc-validator.jar --pkc <pkc-file> {--ca <ca-file> | --req <req-file>}");
		outputStream.println("  --pkc  the PKC chain file to check.");
		outputStream.println("  --ca   the Thales HSM Root CA file.");
		outputStream.println("  --req  the Certificate Signing Request file.");
		outputStream.println("");

		System.exit(code);
	}

	static void usage() {
		usage(1);
	}

	public static void main(String[] args) {
		String pkcFile = "";
		String caFile = "";
		String csrFile = "";
		byte[] pkcdata = null;
		byte[] cacert = null;
		byte[] csrEncoded = null;

		/*
		 * Process command line arguments.
		 */
		for (int i = 0; i < args.length; ++i) {
			if (args[i].equalsIgnoreCase("--pkc")) {
				if (++i >= args.length)
					usage();

				pkcFile = args[i];
			} else if (args[i].equalsIgnoreCase("--ca")) {
				if (++i >= args.length)
					usage();

				caFile = args[i];
			} else if (args[i].equalsIgnoreCase("--req")) {
				if (++i >= args.length)
					usage();

				csrFile = args[i];
			} else if (args[i].equalsIgnoreCase("--help") ||
					args[i].equalsIgnoreCase("-h")) {
				usage(0);
			} else {
				usage();
			}
		}

		if (pkcFile.equalsIgnoreCase("") ||
				(caFile.equalsIgnoreCase("") && csrFile.equalsIgnoreCase(""))) {
			System.err.println("Error: Missing argument(s)");

			usage();
		}

		// Read all files.
		try {
			pkcdata = Files.readAllBytes(Paths.get(pkcFile));

			PemReader pemReader = null;

			if (!caFile.equalsIgnoreCase("")) {
				if (isPEM(caFile)) {
					pemReader = new PemReader(new FileReader(caFile));
					cacert = pemReader.readPemObject().getContent();
					pemReader.close();
				} else {
					cacert = Files.readAllBytes(Paths.get(caFile));
				}
			}

			if (!csrFile.equalsIgnoreCase("")) {
				if (isPEM(csrFile)) {
					pemReader = new PemReader(new FileReader(csrFile));
					csrEncoded = pemReader.readPemObject().getContent();
					pemReader.close();
				} else {
					csrEncoded = Files.readAllBytes(Paths.get(csrFile));
				}
			}
		} catch (IOException ex) {
			System.err.println("Error: could not read file '" + ex.getMessage() + "'");
		}

		PkcValidator validator = new PkcValidator();

		try {
			ByteArrayInputStream bais = new ByteArrayInputStream(pkcdata);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");

			// Extract the certification path from the PKCS7 SignedData structure.
			CertPath cp = cf.generateCertPath(bais, "PKCS7");

			final List<? extends Certificate> certChain = cp.getCertificates();

			if (!validator.validateCertificateChain(certChain)) {
				System.err.println("\nError: Cert chain validation failed.");

				System.exit(1);
			}

			root = validator.getRoot();
			leaf = validator.getLeaf();
		} catch (Exception e) {
			e.printStackTrace(System.err);

			System.exit(1);
		}

		if (cacert != null) {
			try {
				ByteArrayInputStream bais = new ByteArrayInputStream(cacert);
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				Certificate cert = cf.generateCertificate(bais);
				MessageDigest md = MessageDigest.getInstance("SHA1");

				md.update(cert.getEncoded());

				byte[] fingerprint1 = md.digest();

				md = MessageDigest.getInstance("SHA1");
				md.update(root.getEncoded());

				byte[] fingerprint2 = md.digest();

				if (Arrays.compareUnsigned(fingerprint1, fingerprint2) == 0) {
					System.out.println("\nCertificate chain validated against provided rootCA cert.");
					System.out.println("Root CA Fingerprint: "
							+ Hex.toHexString(fingerprint1).replaceAll("..(?!$)", "$0:"));
				} else {
					System.err.println("\nError: Root CA verification failed. Fingerprint does not match.");
					System.err.println("Certificate Fingerprint (From file "
							+ caFile
							+ "): "
							+ Hex.toHexString(fingerprint1).replaceAll("..(?!$)", "$0:"));
					System.err.println("Root CA Fingerprint (From PKC Chain): "
							+ Hex.toHexString(fingerprint2).replaceAll("..(?!$)", "$0:"));
					System.exit(1);
				}
			} catch (Exception e) {
				e.printStackTrace(System.err);

				System.exit(1);
			}
		}

		if (csrEncoded != null) {
			try {
				JcaPKCS10CertificationRequest csr = new JcaPKCS10CertificationRequest(csrEncoded);
				PublicKey pubKey = csr.getPublicKey();

				if (Arrays.compareUnsigned(pubKey.getEncoded(), leaf.getPublicKey().getEncoded()) == 0) {
					System.out.println(
							"\nPublic Key from provided CSR matches public key from pkc certificate chain's leaf certificate.");
				} else {
					System.err.println(
							"\nError: Public key from provided CSR does not match cert chain leaf certificate public key.");
				}
			} catch (Exception e) {
				e.printStackTrace(System.err);
				System.exit(1);
			}
		}
	}

	static boolean isPEM(String file) throws IOException {
		byte[] data;

		try (FileInputStream fis = new FileInputStream(file)) {
			data = new byte[11];
			fis.read(data);
		}

		return ("-----BEGIN ".equals(new String(data)));
	}
}
