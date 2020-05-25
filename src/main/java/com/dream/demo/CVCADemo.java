package com.dream.demo;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAFactory;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CVCCAInfo;
import org.cesecore.certificates.ca.CvcCA;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCProvider;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;

import util.CryptoUtil;
import util.FileUtil;

public class CVCADemo {
	
	// globals
	public static String CVCA_DN = "cn=CVCATest,ou=demo,o=dream,c=KR";
	public static String CVCA_TOKEN_PASSWORD = "test1234";
	public static String CVCA_ALG = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
	public static final String CVCA_DATA = "CVCAFiles/CSCAData";
	public static final String CVCA_TOKEN_DATA = "CVCAFiles/CSCATokenData";
	public static final String CVCA_TOKEN_PROP = "CVCAFiles/CSCATokenProp";
	
	public CVCADemo() {
		CryptoProviderTools.installBCProvider();
		
	}
	
	public void createCVCACert() {
		
	}
	
	public void createLinkCert() {
		
	}
	
	public void createDVCert() {
		
	}
	
	public void createISCert() {
		
	}
	
	/*
	private void saveCVCA(Object saveData) throws IOException {
		// Write to XML
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XMLEncoder encoder = new XMLEncoder(baos);
		encoder.writeObject(saveData);
		encoder.close();
		String data = baos.toString("UTF8");
		FileUtil.saveFile(CVCA_DATA, data.getBytes());
	}

	private X509CA loadCVCA() throws FileNotFoundException {
		// restore
		byte[] caData = FileTools.readFiletoBuffer(CVCA_DATA);
		XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(caData));
		HashMap<?, ?> ca1Data = (HashMap<?, ?>) decoder.readObject();
		decoder.close();

		@SuppressWarnings({ "unchecked", "rawtypes" })
		X509CA ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl((HashMap) ca1Data, 777, CVCA_DN, "CVCATest", CAConstants.CA_ACTIVE, new Date(), new Date());

		return ca;
	}
	
	public void createCVCACert() throws Exception {
	
	final AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();

	// crypto token
	CryptoToken cryptoToken = CryptoUtil.createCryptoToken(CVCA_TOKEN_PASSWORD);
	
	// ca token
	CAToken caToken = CryptoUtil.createCAToken(cryptoToken, CVCA_ALG);
	
	// info
	CVCCAInfo cainfo = new CVCCAInfo(CVCA_DN, "CVCATest", CAConstants.CA_ACTIVE,
			CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "15y", CAInfo.SELFSIGNED, null, caToken);
	cainfo.setDescription("CVCA Test");
	
	// create ca
	CvcCA cvca = (CvcCA) CAFactory.INSTANCE.getCvcCaImpl(cainfo);
	
	cvca.setCAToken(caToken);

	// save
	CryptoUtil.saveCryptoToken(cryptoToken,CVCA_TOKEN_PROP,CVCA_TOKEN_DATA);

	// issue CVCA certificate
	final PublicKey publicKey = cryptoToken
			.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
	final PrivateKey privateKey = cryptoToken
			.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			
	CAReferenceField caRef = new CAReferenceField("KR", "CVCA001", "00001");
    HolderReferenceField holderRef = new HolderReferenceField("KR", "CVCA001", "00001");
    
    CVCertificate cv = createCvcCertificate(publicKey, privateKey, caRef, holderRef, CVCA_ALG , AuthorizationRoleEnum.CVCA,
    		BouncyCastleProvider.PROVIDER_NAME);
    Certificate cacert = new CardVerifiableCertificate(cv);        
    List<Certificate> cachain = new ArrayList<>();
    cachain.add(cacert);
    cvca.setCertificateChain(cachain);

	FileUtil.saveFile("CVCAFiles/CVCACert.ber", cacert.getEncoded());

	System.out.println(CertTools.dumpCertificateAsString(cacert));

	// save
	saveCVCA(cvca.saveData());
	
}

public static CVCertificate createCvcCertificate(PublicKey publicKey, PrivateKey privateKey, CAReferenceField caRef,
        HolderReferenceField holderRef, String algorithm, AuthorizationRoleEnum role, String provider) throws Exception {
    
    Calendar cal1 = Calendar.getInstance();
    Date validFrom = cal1.getTime();

    Calendar cal2 = Calendar.getInstance();
    cal2.add(Calendar.MONTH, 3);
    Date validTo = cal2.getTime();
    
    return CertificateGenerator.createCertificate(publicKey, privateKey, algorithm, caRef, holderRef, role,
            AccessRightEnum.READ_ACCESS_DG3_AND_DG4, validFrom, validTo, provider);
}*/
	
}
