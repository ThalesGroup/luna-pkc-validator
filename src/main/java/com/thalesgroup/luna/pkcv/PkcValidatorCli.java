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
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.pem.PemReader;

public class PkcValidatorCli {
	static Certificate leaf;
	static Certificate root;
	static String rootRSAdn="CN=Chrysalis-ITS Root, O=Chrysalis-ITS Inc., L=Ottawa, ST=Ontario, C=CA";
	static String rootECCdn="CN=\"SafeNet ECC Manufacturer Integrity Module \", OU=Luna Manufacturer Integrity ECC, O=\"SafeNet, Inc.\", C=US";
	
	static final String[] PKCEKURSA = new String[] {"1.3.6.1.4.1.12383.1.13",
            "1.3.6.1.4.1.12383.1.12",
             "1.3.6.1.4.1.12383.1.8",
             "1.3.6.1.4.1.12383.1.7",
             "1.3.6.1.4.1.12383.1.1"

           };


     static final String[] PKCEKUECC = new String[] { "1.3.6.1.4.1.12383.1.13",
             "1.3.6.1.4.1.12383.1.15",
             "1.3.6.1.4.1.12383.1.14",
           };


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
	
	static boolean isPEM(String file) throws IOException {
		byte[] data;

		try (FileInputStream fis = new FileInputStream(file)) {
			data = new byte[11];
			fis.read(data);
		}

		return ("-----BEGIN ".equals(new String(data)));
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
			
            @SuppressWarnings("unchecked")
			final List<X509Certificate> x509CertificateList = (List<X509Certificate>) cp.getCertificates();
            
            //Check the size of the PKC chain. RSA keys have different pkc chain than ECC
			
			if (x509CertificateList.size() >3 )
			{
			    // Checking RSA key PKC chain Extensions
				if(!validator.validatePKCExtensions(x509CertificateList, PKCEKURSA)) {
			    	
			    	System.out.println("PKC is not from valid Luna HSM");
			    	System.exit(1);
			    } 
			
			} else
				
			{
				//Checking ECC key PKC chain extensions 
				if(!validator.validatePKCExtensions(x509CertificateList, PKCEKUECC))
				{
					{
				    	
				    	System.out.println("PKC is not from valid Luna HSM");
				    	System.exit(1);
				    }
				}
			}

			//Print the serial number of the HSM.
			if(!validator.printSerialNumberofHSM(x509CertificateList.get(0))) {
				
				System.out.println("Could not determine the serial number of HSM");
			}
			
            //Check the validity of certificate chain.
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

		//Check the root certificate provided against root certificate in PKC chain.
		if (cacert != null) {
			try {
				ByteArrayInputStream bais = new ByteArrayInputStream(cacert);
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				Certificate cert = cf.generateCertificate(bais);
				
				X509Certificate rootCert = (X509Certificate) cert;
				
				List<String> extendedKeyUsage = rootCert.getExtendedKeyUsage();
				
				String certSubjectdn=rootCert.getSubjectDN().toString();
				String certIssuerdn=rootCert.getIssuerDN().toString();
				
				
	          if((certSubjectdn.equals(rootRSAdn)&&certIssuerdn.equals(rootRSAdn))||(certSubjectdn.equals(rootECCdn)&&certIssuerdn.equals(rootECCdn)))	{		 
				 System.out.println("Subject: " + rootCert.getSubjectDN());
		            System.out.println("Issuer: " + rootCert.getIssuerDN());
	          }   else {
	        	  System.out.println("Root certificate is not issued by Thales");
	          }
		           
				
				 if (extendedKeyUsage != null) {
		              
		                for ( String usage : extendedKeyUsage) {
		                	
		                	
		                	if (usage.equals("1.3.6.1.4.1.12383.1.1") || usage.equals("1.3.6.1.4.1.12383.1.14")) {
		                		System.out.println("EKU matched for provided root cert");
		                	}
		                	else {
		                		System.out.println("Root cert provided is not valid Luna HSM Certificate ");
		                		System.exit(1);
		                	}
		                    
		                }
		                    
				 }
				 
				
				PublicKey pk = cert.getPublicKey();
				
				if (pk.equals(root.getPublicKey())) {
					System.out.println("Certificate chain validated against root CA Cert");
				}
				
				else {
					System.out.println("\\nError: Root CA verification failed. ");
					
				}
				
				
				
			} catch (Exception e) {
				e.printStackTrace(System.err);

				System.exit(1);
			}
		}
		
		//This validates the pkc chain against CSR

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

	
}
