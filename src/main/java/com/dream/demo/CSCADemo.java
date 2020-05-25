package com.dream.demo;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.lang.time.DateUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.icao.CscaMasterList;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAFactory;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;

import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import util.CryptoUtil;
import util.FileUtil;

public class CSCADemo {

	private static String CSCA_DN = "cn=CSCATest,ou=demo,o=dream,c=KR";
	public static String NEXT_CSCA_DN = "cn=NextCSCATest,ou=demo,o=dream,c=KR";
	public static String CSCA_ALG = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
	private static final String CSCA_DATA = "CSCAFiles/CSCAData";
	private static final String CSCA_TOKEN_DATA = "CSCAFiles/CSCATokenData";
	private static final String CSCA_TOKEN_PROP = "CSCAFiles/CSCATokenProp";
	public static final String END_ENTITY_SUB_DN = "cn=EETest,ou=demo,o=dream,c=KR";
	private static final String CSCA_TOKEN_PASSWORD = "test1234";

	public CSCADemo() {
		CryptoProviderTools.installBCProviderIfNotAvailable();
	}

	public void createCSCACert()
			throws CertificateParsingException, OperatorCreationException, CryptoTokenOfflineException,
			InvalidAlgorithmException, InvalidAlgorithmParameterException, IOException, CertificateEncodingException {

		X509CA csca = this.createX509CA(CSCA_DN, CSCA_ALG);

		X509Certificate cscaCert = (X509Certificate) csca.getCACertificate();

		FileUtil.saveFile("CSCAFiles/CSCACert.der", cscaCert.getEncoded());

		System.out.println(CertTools.dumpCertificateAsString(cscaCert));

		// save
		saveCSCA(csca.saveData());
	}

	public X509CA createX509CA(String cadn, String sigAlg)
			throws CertificateParsingException, OperatorCreationException, CryptoTokenOfflineException,
			InvalidAlgorithmException, InvalidAlgorithmParameterException, IOException {

		final AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();

		CryptoToken cryptoToken = CryptoUtil.createCryptoToken(CSCA_TOKEN_PASSWORD);
		CAToken caToken = CryptoUtil.createCAToken(cryptoToken, sigAlg);

		// No extended services
		X509CAInfo cainfo = new X509CAInfo(cadn, "CSCATest", CAConstants.CA_ACTIVE,
				CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "15y", CAInfo.SELFSIGNED, null, caToken);
		cainfo.setDescription("CSCA Test");

		// create ca
		X509CA x509ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);

		x509ca.setCAToken(caToken);

		// save
		CryptoUtil.saveCryptoToken(cryptoToken, CSCA_TOKEN_PROP, CSCA_TOKEN_DATA);

		// crl dp -- use in only crl
		final String cdpURL = "http://www.demo.org/bar/bar.crl;http://www.demo.org/foo/foo.crl";
		cainfo = (X509CAInfo) x509ca.getCAInfo();
		cainfo.setUseCrlDistributionPointOnCrl(true);
		cainfo.setDefaultCRLDistPoint(cdpURL);
		x509ca.updateCA(cryptoToken, cainfo, cceConfig);

		// AIA for crl
		List<String> authorityInformationAccess = new ArrayList<>();
		authorityInformationAccess.add("http://example.com/0");
		authorityInformationAccess.add("http://example.com/1");
		x509ca.setAuthorityInformationAccess(authorityInformationAccess);

		// AIA for cert
		x509ca.setCertificateAiaDefaultCaIssuerUri(authorityInformationAccess);
		final List<String> ocspUrls = new ArrayList<String>();
		ocspUrls.add("http://ca-defined.ocsp.service.locator.url.sw");
		x509ca.setDefaultOCSPServiceLocator(ocspUrls.get(0));

		// A CA certificate
		final PublicKey publicKey = cryptoToken
				.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
		final PrivateKey privateKey = cryptoToken
				.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
		int keyusage = X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign;

		X509Certificate cacert = CertTools.genSelfCertForPurpose(cadn, 15 * 365, "1.1.1.1", privateKey, publicKey,
				sigAlg, true, keyusage, new Date(), DateUtils.addYears(new Date(), 5),
				BouncyCastleProvider.PROVIDER_NAME);
		List<Certificate> cachain = new ArrayList<>();
		cachain.add(cacert);
		x509ca.setCertificateChain(cachain);

		return x509ca;
	}

	public void createLinkCert(String optionalNewDN)
			throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, IOException,
			NoSuchSlotException, InvalidAlgorithmParameterException, CertificateEncodingException,
			InvalidAlgorithmException, CertificateParsingException, OperatorCreationException {

		boolean changeName = false;
		String nextCSCADN = CSCA_DN;

		if (optionalNewDN != null && !optionalNewDN.equals(CSCA_DN)) {
			changeName = true;
			nextCSCADN = optionalNewDN;
		}

		if (!changeName) {
			nextCSCADN = CSCA_DN;
		}

		// restore csca
		X509CA currentCA = loadCSCA();
		FileUtil.saveFile("CSCAFiles/CSCACert.der", currentCA.getCACertificate().getEncoded());

		// load current ca token
		CryptoToken cryptoToken = CryptoUtil.loadCSCACryptoToken(CSCA_TOKEN_PROP, CSCA_TOKEN_DATA, CSCA_TOKEN_PASSWORD);
		CAToken caToken = currentCA.getCAToken();

		// generate new keypair with next keypair alias (alias is generated
		// using ca token)
		cryptoToken.generateKeyPair(CryptoUtil.getTestKeySpec(CSCA_ALG), caToken.generateNextSignKeyAlias());

		// move curr key pair to prev and next keypair to current
		caToken.activateNextSignKey();

		// create new self sign csca
		// String nextCADN = "c=KR,o=dream,ou=demo,cn=CSCALinkTest";
		X509CAInfo nextCAinfo = new X509CAInfo(nextCSCADN, "NEXT_CSCATest", CAConstants.CA_ACTIVE,
				CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "15y", CAInfo.SELFSIGNED, null, caToken);
		nextCAinfo.setDescription("RSA CSCA Test");
		X509CA nextCA = (X509CA) CAFactory.INSTANCE.getX509CAImpl(nextCAinfo);
		nextCA.setCAToken(caToken);

		// next CA certificate
		final PublicKey publicKey = cryptoToken
				.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
		final PrivateKey privateKey = cryptoToken
				.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));

		int keyusage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;

		X509Certificate newcacert = CertTools.genSelfCertForPurpose(nextCSCADN, 15 * 365, "1.1.1.1", privateKey,
				publicKey, CSCA_ALG, true, keyusage, new Date(), DateUtils.addYears(new Date(), 5),
				BouncyCastleProvider.PROVIDER_NAME);
		List<Certificate> cachain = new ArrayList<>();
		cachain.add(newcacert);
		nextCA.setCertificateChain(cachain);

		CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
		AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();

		List<Certificate> cachain2 = new ArrayList<>();
		cachain2.add(currentCA.getCACertificate());

		nextCA.setRenewedCertificateChain(cachain2);
		// link cert has expiry date of current csca and starting date of next
		if (changeName) {
			nextCA.createOrRemoveLinkCertificateDuringCANameChange(cryptoToken, true, certProfile, cceConfig,
					currentCA.getCACertificate());
		} else {
			nextCA.createOrRemoveLinkCertificate(cryptoToken, true, certProfile, cceConfig,
					currentCA.getCACertificate());
		}

		FileUtil.saveFile("CSCAFiles/LinkCert.der", nextCA.getLatestLinkCertificate());
		FileUtil.saveFile("CSCAFiles/NextCSCACert.der", nextCA.getCACertificate().getEncoded());

	}

	public PKCS10CertificationRequest createPKCS10Request(String subjectDN)
			throws IOException, InvalidAlgorithmParameterException, OperatorCreationException {
		// Create a P10 with extensions, in this case altNames with a DNS name
		ASN1EncodableVector altnameattr = new ASN1EncodableVector();
		altnameattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
		// AltNames
		// String[] namearray = altnames.split(",");
		GeneralNames san = CertTools.getGeneralNamesFromAltName("dNSName=foo1.bar.com");
		ExtensionsGenerator extgen = new ExtensionsGenerator();
		extgen.addExtension(Extension.subjectAlternativeName, false, san);

		Extensions exts = extgen.generate();

		altnameattr.add(new DERSet(exts));

		// Add a challenge password as well
		/*
		 * ASN1EncodableVector pwdattr = new ASN1EncodableVector();
		 * pwdattr.add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
		 * ASN1EncodableVector pwdvalues = new ASN1EncodableVector();
		 * pwdvalues.add(new DERUTF8String("foo123")); pwdattr.add(new
		 * DERSet(pwdvalues));
		 */

		// Complete the Attribute section of the request, the set (Attributes)
		// contains one sequence (Attribute)
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new DERSequence(altnameattr));
		// v.add(new DERSequence(pwdattr));
		DERSet attributes = new DERSet(v);

		// Create the PKCS10
		X500Name dn = new X500Name(subjectDN);

		KeyPair keyPair = CryptoUtil.genTestKeyPair(CSCA_ALG);

		PKCS10CertificationRequest basicpkcs10 = CertTools.genPKCS10CertificationRequest(CSCA_ALG, dn,
				keyPair.getPublic(), attributes, keyPair.getPrivate(), null);

		FileUtil.saveFile("CSCAFiles/MLS.key", keyPair.getPrivate().getEncoded());
		FileUtil.saveFile("CSCAFiles/PKCSReq.p10", basicpkcs10.getEncoded());

		return basicpkcs10;
	}

	public void createDSCertWithDocType() throws Exception {

		// restore csca
		X509CA ca = loadCSCA();

		// get csca token data
		CryptoToken cryptoToken = CryptoUtil.loadCSCACryptoToken(CSCA_TOKEN_PROP, CSCA_TOKEN_DATA, CSCA_TOKEN_PASSWORD);

		// load pkca10 request
		RequestMessage requestMsg = RequestMessageUtils
				.genPKCS10RequestMessage(FileTools.readFiletoBuffer("CSCAFiles/PKCSReq.p10"));

		// ds cert
		EndEntityInformation user = new EndEntityInformation("DSTest", "cn=DSTest,ou=demo,o=dream,c=KR", ca.getCAId(),
				"rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0, 0,
				EndEntityConstants.TOKEN_USERGEN, null);

		// profile
		CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

		// doc type
		cp.setDocumentTypeList(new ArrayList<String>(Arrays.asList("P", "ID")));
		cp.setUseDocumentTypeList(true);

		// pol id
		cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", null, null));
		cp.setUseCertificatePolicies(true);

		// private key usage
		// cp.setPrivateKeyUsagePeriodStartOffset(0);
		cp.setPrivateKeyUsagePeriodLength((DateUtils.addMonths(new Date(), 3).getTime() - new Date().getTime()) / 1000);
		cp.setUsePrivateKeyUsagePeriodNotBefore(true);
		cp.setUsePrivateKeyUsagePeriodNotAfter(true);

		// crl dis point
		cp.setCRLDistributionPointURI("http://www.demo.org/bar/bar.crl;http://www.demo.org/foo/foo.crl");
		cp.setUseCRLDistributionPoint(true);

		// aia
		cp.setUseAuthorityInformationAccess(true);
		cp.setCaIssuers(Arrays.asList("http://certificate-profile.ca.issuer.uri1.sw",
				"http://certificate-profile.ca.issuer.uri2.sw"));
		cp.setOCSPServiceLocatorURI("http://certificate-profile.ocsp.service.locator.url.sw");
		cp.setUseDefaultCAIssuer(true);
		cp.setUseDefaultOCSPServiceLocator(true);

		// remove basic constraints
		cp.setUseBasicConstraints(false);

		// basic key usage
		cp.getAllowKeyUsageOverride();
		cp.setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
		cp.setKeyUsage(CertificateConstants.NONREPUDIATION, false);
		cp.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, false);
		cp.setKeyUsageCritical(true);

		cp.setEncodedValidity("10y");

		AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();

		X509Certificate dsCert = (X509Certificate) ca.generateCertificate(cryptoToken, user, requestMsg,
				requestMsg.getRequestPublicKey(), KeyUsage.digitalSignature, new Date(),
				DateUtils.addYears(new Date(), 10), cp, requestMsg.getRequestExtensions(), "00000", cceConfig);

		FileUtil.saveFile("CSCAFiles/DSCert.der", dsCert.getEncoded());

	}

	public void createMasterListSignerCert() throws Exception {
		// restore csca
		X509CA ca = loadCSCA();

		// get csca token data
		CryptoToken cryptoToken = CryptoUtil.loadCSCACryptoToken(CSCA_TOKEN_PROP, CSCA_TOKEN_DATA, CSCA_TOKEN_PASSWORD);

		// load pkca10 request
		RequestMessage requestMsg = RequestMessageUtils
				.genPKCS10RequestMessage(FileTools.readFiletoBuffer("CSCAFiles/PKCSReq.p10"));

		// ds cert
		EndEntityInformation user = new EndEntityInformation("MasterListSignerCertTest",
				"cn=MasterListSignerCertTest,ou=demo,o=dream,c=KR", ca.getCAId(),
				"rfc822Name=MasterListSignerCertTest@demo.com", "MasterListSignerCertTest@demo.com",
				new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);

		// profile
		CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

		// private key usage
		// cp.setPrivateKeyUsagePeriodStartOffset(0);
		cp.setPrivateKeyUsagePeriodLength((DateUtils.addMonths(new Date(), 3).getTime() - new Date().getTime()) / 1000);
		cp.setUsePrivateKeyUsagePeriodNotBefore(true);
		cp.setUsePrivateKeyUsagePeriodNotAfter(true);

		// crl dis point
		cp.setCRLDistributionPointURI("http://www.demo.org/bar/bar.crl;http://www.demo.org/foo/foo.crl");
		cp.setUseCRLDistributionPoint(true);

		// aia
		cp.setUseAuthorityInformationAccess(true);
		cp.setCaIssuers(Arrays.asList("http://certificate-profile.ca.issuer.uri1.sw",
				"http://certificate-profile.ca.issuer.uri2.sw"));
		cp.setOCSPServiceLocatorURI("http://certificate-profile.ocsp.service.locator.url.sw");
		cp.setUseDefaultCAIssuer(true);
		cp.setUseDefaultOCSPServiceLocator(true);

		// remove basic constraints
		cp.setUseBasicConstraints(false);

		// basic key usage
		cp.getAllowKeyUsageOverride();
		cp.setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
		cp.setKeyUsage(CertificateConstants.NONREPUDIATION, false);
		cp.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, false);
		cp.setKeyUsageCritical(true);

		// master list signer ext key usage
		cp.setUseExtendedKeyUsage(true);
		cp.setExtendedKeyUsageCritical(true);
		ArrayList<String> list = new ArrayList<>();
		list.add(ICAOObjectIdentifiers.id_icao_cscaMasterListSigningKey.getId());
		cp.setExtendedKeyUsageOids(list);

		AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();

		cp.setEncodedValidity("10y");

		X509Certificate dsCert = (X509Certificate) ca.generateCertificate(cryptoToken, user, requestMsg,
				requestMsg.getRequestPublicKey(), KeyUsage.digitalSignature, new Date(),
				DateUtils.addYears(new Date(), 10), cp, requestMsg.getRequestExtensions(), "00000", cceConfig);

		FileUtil.saveFile("CSCAFiles/MLSCert.der", dsCert.getEncoded());
	}

	public void createDeviationListSignerCert() throws Exception {
		// restore csca
		X509CA ca = loadCSCA();

		// get csca token data
		CryptoToken cryptoToken = CryptoUtil.loadCSCACryptoToken(CSCA_TOKEN_PROP, CSCA_TOKEN_DATA, CSCA_TOKEN_PASSWORD);

		// load pkca10 request
		RequestMessage requestMsg = RequestMessageUtils
				.genPKCS10RequestMessage(FileTools.readFiletoBuffer("CSCAFiles/PKCSReq.p10"));

		// ds cert
		EndEntityInformation user = new EndEntityInformation("DeviationListSignerCertTest",
				"cn=DeviationListSignerCertTest,ou=demo,o=dream,c=KR", ca.getCAId(),
				"rfc822Name=MasterListSignerCertTest@demo.com", "MasterListSignerCertTest@demo.com",
				new EndEntityType(EndEntityTypes.ENDUSER), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);

		// profile
		CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

		// private key usage
		// cp.setPrivateKeyUsagePeriodStartOffset(0);
		cp.setPrivateKeyUsagePeriodLength((DateUtils.addMonths(new Date(), 3).getTime() - new Date().getTime()) / 1000);
		cp.setUsePrivateKeyUsagePeriodNotBefore(true);
		cp.setUsePrivateKeyUsagePeriodNotAfter(true);

		// crl dis point
		cp.setCRLDistributionPointURI("http://www.demo.org/bar/bar.crl;http://www.demo.org/foo/foo.crl");
		cp.setUseCRLDistributionPoint(true);

		// aia
		cp.setUseAuthorityInformationAccess(true);
		cp.setCaIssuers(Arrays.asList("http://certificate-profile.ca.issuer.uri1.sw",
				"http://certificate-profile.ca.issuer.uri2.sw"));
		cp.setOCSPServiceLocatorURI("http://certificate-profile.ocsp.service.locator.url.sw");
		cp.setUseDefaultCAIssuer(true);
		cp.setUseDefaultOCSPServiceLocator(true);

		// remove basic constraints
		cp.setUseBasicConstraints(false);

		// basic key usage
		cp.getAllowKeyUsageOverride();
		cp.setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
		cp.setKeyUsage(CertificateConstants.NONREPUDIATION, false);
		cp.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, false);
		cp.setKeyUsageCritical(true);

		// deviation list signer ext key usage
		cp.setUseExtendedKeyUsage(true);
		cp.setExtendedKeyUsageCritical(true);
		ArrayList<String> list = new ArrayList<>();
		list.add(ICAOObjectIdentifiers.id_icao_mrtd_security.branch("8").getId());
		cp.setExtendedKeyUsageOids(list);

		AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();

		cp.setEncodedValidity("10y");

		X509Certificate dsCert = (X509Certificate) ca.generateCertificate(cryptoToken, user, requestMsg,
				requestMsg.getRequestPublicKey(), KeyUsage.digitalSignature, new Date(),
				DateUtils.addYears(new Date(), 10), cp, requestMsg.getRequestExtensions(), "00000", cceConfig);

		FileUtil.saveFile("CSCAFiles/DLSCert.der", dsCert.getEncoded());
	}

	public void createCRL() throws Exception {
		// restore csca
		X509CA x509ca = loadCSCA();

		// get csca token data
		CryptoToken cryptoToken = CryptoUtil.loadCSCACryptoToken(CSCA_TOKEN_PROP, CSCA_TOKEN_DATA, CSCA_TOKEN_PASSWORD);

		// load clien cert
		// CertificateFactory certFact=CertificateFactory.getInstance("X.509");
		// X509Certificate
		// cert=(X509Certificate)certFact.generateCertificate(new
		// ByteArrayInputStream(FileTools.readFiletoBuffer("CSCAFiles/DSCert.der")));
		X509Certificate cert = (X509Certificate) CertTools
				.getCertfromByteArray(FileTools.readFiletoBuffer("CSCAFiles/DSCert.der"), X509Certificate.class);

		// Create a CRL
		Collection<RevokedCertInfo> revcerts = new ArrayList<>();
		Calendar before = Calendar.getInstance();
		before.set(Calendar.MILLISECOND, 0);
		final Date justBefore = before.getTime(); // Round to seconds

		// Revoke some cert
		Date revDate = new Date();
		revcerts.add(new RevokedCertInfo(CertTools.getFingerprintAsString(cert).getBytes(),
				CertTools.getSerialNumber(cert).toByteArray(), revDate.getTime(),
				RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, CertTools.getNotAfter(cert).getTime()));

		X509CRLHolder crl = x509ca.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revcerts, 1);

		FileUtil.saveFile("CSCAFiles/CRL.crl", crl.getEncoded());

	}

	public void createMasterList() throws Exception {

		// load master list signer key
		/* Check to see if this is in an EncryptedPrivateKeyInfo structure. */
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(FileTools.readFiletoBuffer("CSCAFiles/MLS.key"));
		/*
		 * Now it's in a PKCS#8 PrivateKeyInfo structure. Read its Algorithm OID
		 * and use that to construct a KeyFactory.
		 */
		ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(spec.getEncoded()));
		PrivateKeyInfo pki = PrivateKeyInfo.getInstance(bIn.readObject());
		String algOid = pki.getPrivateKeyAlgorithm().getAlgorithm().getId();

		PrivateKey MLSkey = KeyFactory.getInstance(algOid).generatePrivate(spec);
		X509Certificate MLSCert = CertTools.getCertfromByteArray(FileTools.readFiletoBuffer("CSCAFiles/MLSCert.der"),
				X509Certificate.class);

		// create the output stream
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		bOut.write(FileTools.readFiletoBuffer("CSCAFiles/CSCACert.der"));
		bOut.write(FileTools.readFiletoBuffer("CSCAFiles/DSCert.der"));
		bOut.write(FileTools.readFiletoBuffer("CSCAFiles/DLSCert.der"));

		bOut.close();

		// create ml
		// set up the generator
		////////////////////////
		X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(MLSCert.getEncoded());

		String pubkeyAlgorithm = MLSCert.getPublicKey().getAlgorithm();
		String certAlgorithm = "";

		if (pubkeyAlgorithm.equals("RSA")) {
			certAlgorithm = "SHA256WITHRSA";
		} else if (pubkeyAlgorithm.equals("ECDSA")) {
			certAlgorithm = "SHA256WITHECDSA";
		} else if (pubkeyAlgorithm.equals("DSA")) {
			certAlgorithm = "SHA256WITHDSA";
		} else {
			certAlgorithm = "SHA256WITHRSA";
		}

		X509Certificate cscaCert = CertTools.getCertfromByteArray(FileTools.readFiletoBuffer("CSCAFiles/CSCACert.der"),
				X509Certificate.class);

		// create master list content
		JcaX509CertificateHolder[] hollist = CertTools
				.convertToX509CertificateHolder(new X509Certificate[] { cscaCert });

		ASN1EncodableVector certVec = new ASN1EncodableVector();
		certVec.add(hollist[0].toASN1Structure());
		certVec.add(hollist[0].toASN1Structure());

		org.bouncycastle.asn1.x509.Certificate cert[] = new org.bouncycastle.asn1.x509.Certificate[2];
		cert[0] = hollist[0].toASN1Structure();
		cert[1] = hollist[0].toASN1Structure();

		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new ASN1Integer(0)); // master list version
		v.add(new DERSet(cert));

		byte[] tbsData = new DERSequence(v).getEncoded();
		// System.out.println(">>>>> encoded data : " + new
		// java.math.BigInteger(1, tbsData).toString(16));

		CMSTypedData message = new CMSProcessableByteArray(ICAOObjectIdentifiers.id_icao_cscaMasterList, tbsData);

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(certAlgorithm);

		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter privateKeyParameter = PrivateKeyFactory.createKey(MLSkey.getEncoded());

		BcContentSignerBuilder signBuilder = null;
		if (pubkeyAlgorithm.equals("RSA")) {
			signBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
		} else if (pubkeyAlgorithm.equals("EC")) {
			signBuilder = new BcECContentSignerBuilder(sigAlgId, digAlgId);
		} else if (pubkeyAlgorithm.equals("DSA")) {
			signBuilder = new BcDSAContentSignerBuilder(sigAlgId, digAlgId);
		} else {
			signBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
		}

		ContentSigner signer = signBuilder.build(privateKeyParameter);

		SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(
				new BcDigestCalculatorProvider());
		SignerInfoGenerator infoGenerator = signerInfoGeneratorBuilder.build(signer, x509CertificateHolder);

		CMSSignedDataGenerator dataGenerator = new CMSSignedDataGenerator();
		dataGenerator.addSignerInfoGenerator(infoGenerator);

		dataGenerator.addCertificate(x509CertificateHolder);
		dataGenerator.addCertificate(new X509CertificateHolder(FileTools.readFiletoBuffer("CSCAFiles/CSCACert.der")));

		CMSSignedData signedData = dataGenerator.generate(message, true);

		FileUtil.saveFile("CSCAFiles/MasterList.ml", signedData.getEncoded());

	}

	public void createMasterList2() throws Exception {

		// load master list signer key
		/* Check to see if this is in an EncryptedPrivateKeyInfo structure. */
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(FileTools.readFiletoBuffer("CSCAFiles/MLS.key"));
		/*
		 * Now it's in a PKCS#8 PrivateKeyInfo structure. Read its Algorithm OID
		 * and use that to construct a KeyFactory.
		 */
		ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(spec.getEncoded()));
		PrivateKeyInfo pki = PrivateKeyInfo.getInstance(bIn.readObject());
		String algOid = pki.getPrivateKeyAlgorithm().getAlgorithm().getId();

		PrivateKey MLSkey = KeyFactory.getInstance(algOid).generatePrivate(spec);

		X509Certificate MLSCert = CertTools.getCertfromByteArray(FileTools.readFiletoBuffer("CSCAFiles/MLSCert.der"),
				X509Certificate.class);

		// create the output stream
		/*ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		bOut.write(FileTools.readFiletoBuffer("CSCAFiles/CSCACert.der"));
		bOut.write(FileTools.readFiletoBuffer("CSCAFiles/DSCert.der"));
		
		bOut.close();
		*/
		
		// create ml
		// set up the generator
		////////////////////////
		X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(MLSCert.getEncoded());

		String pubkeyAlgorithm = MLSCert.getPublicKey().getAlgorithm();
		String certAlgorithm = "";

		if (pubkeyAlgorithm.equals("RSA")) {
			certAlgorithm = "SHA256WITHRSA";
		} else if (pubkeyAlgorithm.equals("ECDSA")) {
			certAlgorithm = "SHA256WITHECDSA";
		} else if (pubkeyAlgorithm.equals("DSA")) {
			certAlgorithm = "SHA256WITHDSA";
		} else {
			certAlgorithm = "SHA256WITHRSA";
		}

		// csca cert
		X509Certificate cscaCert = CertTools.getCertfromByteArray(FileTools.readFiletoBuffer("CSCAFiles/CSCACert.der"),
				X509Certificate.class);

		// create master list content
		JcaX509CertificateHolder[] hollist = CertTools
				.convertToX509CertificateHolder(new X509Certificate[] { cscaCert });

		org.bouncycastle.asn1.x509.Certificate certList[] = new org.bouncycastle.asn1.x509.Certificate[1];
		certList[0] = hollist[0].toASN1Structure();
		//certList[1] = hollist[0].toASN1Structure();

		CscaMasterList ml = new CscaMasterList(certList);
		
		System.out.println(">>>>> encoded data : " + new java.math.BigInteger(1, ml.getEncoded()).toString(16));
		
		CMSTypedData message = new CMSProcessableByteArray(ICAOObjectIdentifiers.id_icao_cscaMasterList,
				ml.toASN1Primitive().getEncoded());   
		
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(certAlgorithm);

		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter privateKeyParameter = PrivateKeyFactory.createKey(MLSkey.getEncoded());

		BcContentSignerBuilder signBuilder = null;
		if (pubkeyAlgorithm.equals("RSA")) {
			signBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
		} else if (pubkeyAlgorithm.equals("EC")) {
			signBuilder = new BcECContentSignerBuilder(sigAlgId, digAlgId);
		} else if (pubkeyAlgorithm.equals("DSA")) {
			signBuilder = new BcDSAContentSignerBuilder(sigAlgId, digAlgId);
		} else {
			signBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
		}

		ContentSigner signer = signBuilder.build(privateKeyParameter);

		SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(
				new BcDigestCalculatorProvider());
		SignerInfoGenerator infoGenerator = signerInfoGeneratorBuilder.build(signer, x509CertificateHolder);

		CMSSignedDataGenerator dataGenerator = new CMSSignedDataGenerator();
		dataGenerator.addSignerInfoGenerator(infoGenerator);

		dataGenerator.addCertificate(x509CertificateHolder);
		dataGenerator.addCertificate(new X509CertificateHolder(FileTools.readFiletoBuffer("CSCAFiles/CSCACert.der")));

		CMSSignedData signedData = dataGenerator.generate(message, true);

		System.out.println(">>>>> ML data : " + new java.math.BigInteger(1, signedData.getEncoded()).toString(16));
		
		FileUtil.saveFile("CSCAFiles/MasterList2.ml", signedData.getEncoded());
	}

	public void createMasterList3() throws Exception {

		// load master list signer key
		/* Check to see if this is in an EncryptedPrivateKeyInfo structure. */
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(FileTools.readFiletoBuffer("CSCAFiles/MLS.key"));
		/*
		 * Now it's in a PKCS#8 PrivateKeyInfo structure. Read its Algorithm OID
		 * and use that to construct a KeyFactory.
		 */
		ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(spec.getEncoded()));
		PrivateKeyInfo pki = PrivateKeyInfo.getInstance(bIn.readObject());
		String algOid = pki.getPrivateKeyAlgorithm().getAlgorithm().getId();

		PrivateKey MLSkey = KeyFactory.getInstance(algOid).generatePrivate(spec);

		X509Certificate MLSCert = CertTools.getCertfromByteArray(FileTools.readFiletoBuffer("CSCAFiles/MLSCert.der"),
				X509Certificate.class);

		// create the output stream
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		bOut.write(FileTools.readFiletoBuffer("CSCAFiles/CSCACert.der"));
		bOut.write(FileTools.readFiletoBuffer("CSCAFiles/DSCert.der"));
		bOut.write(FileTools.readFiletoBuffer("CSCAFiles/DLSCert.der"));

		bOut.close();

		// create ml
		// set up the generator
		////////////////////////
		X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(MLSCert.getEncoded());

		String pubkeyAlgorithm = MLSCert.getPublicKey().getAlgorithm();
		String certAlgorithm = "";

		if (pubkeyAlgorithm.equals("RSA")) {
			certAlgorithm = "SHA256WITHRSA";
		} else if (pubkeyAlgorithm.equals("ECDSA")) {
			certAlgorithm = "SHA256WITHECDSA";
		} else if (pubkeyAlgorithm.equals("DSA")) {
			certAlgorithm = "SHA256WITHDSA";
		} else {
			certAlgorithm = "SHA256WITHRSA";
		}

		// csca cert
		X509Certificate cscaCert = CertTools.getCertfromByteArray(FileTools.readFiletoBuffer("CSCAFiles/CSCACert.der"),
				X509Certificate.class);

		// create master list content
		JcaX509CertificateHolder[] hollist = CertTools
				.convertToX509CertificateHolder(new X509Certificate[] { cscaCert });

		org.bouncycastle.asn1.x509.Certificate certList[] = new org.bouncycastle.asn1.x509.Certificate[2];
		certList[0] = hollist[0].toASN1Structure();
		certList[1] = hollist[0].toASN1Structure();

		CscaMasterList ml = new CscaMasterList(certList);
		
		///////////////////////

		// Data to sign
		byte[] dataToSign = ml.getEncoded();
		
		// compute signature:
		Signature signature = Signature.getInstance(certAlgorithm);
		signature.initSign(MLSkey);
		signature.update(dataToSign);
		byte[] signedData = signature.sign();

		// load X500Name
		sun.security.x509.X500Name xName = new sun.security.x509.X500Name(cscaCert.getSubjectDN().getName());
		// load serial number
		BigInteger serial = hollist[0].getSerialNumber();
		// laod digest algorithm
		AlgorithmId digestAlgorithmId = new AlgorithmId(AlgorithmId.SHA_oid);
		// load signing algorithm
		AlgorithmId signAlgorithmId = new AlgorithmId(AlgorithmId.RSAEncryption_oid);

		// Create SignerInfo:
		SignerInfo sInfo = new SignerInfo(xName, serial, digestAlgorithmId, signAlgorithmId, signedData);
		// Create ContentInfo:
		ContentInfo cInfo = new ContentInfo(new ObjectIdentifier("2.23.136.1.1.2"),
				new DerValue(DerValue.tag_OctetString, dataToSign));
		// Create PKCS7 Signed data
		PKCS7 p7 = new PKCS7(new AlgorithmId[] { digestAlgorithmId }, cInfo,
				new java.security.cert.X509Certificate[] { cscaCert }, new SignerInfo[] { sInfo });
		// Write PKCS7 to bYteArray
		ByteArrayOutputStream bOut1 = new DerOutputStream();
		p7.encodeSignedData(bOut1);
		
		System.out.println(">>>>> ML data : " + new java.math.BigInteger(1, bOut1.toByteArray()).toString(16)); 
		
		FileUtil.saveFile("CSCAFiles/MasterList3.ml", bOut1.toByteArray());
	}

	private void saveCSCA(Object saveData) throws IOException {
		// Write to XML
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XMLEncoder encoder = new XMLEncoder(baos);
		encoder.writeObject(saveData);
		encoder.close();
		String data = baos.toString("UTF8");
		FileUtil.saveFile(CSCA_DATA, data.getBytes());
	}

	private X509CA loadCSCA() throws FileNotFoundException {
		// restore csca
		byte[] caData = FileTools.readFiletoBuffer(CSCA_DATA);
		XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(caData));
		HashMap<?, ?> ca1Data = (HashMap<?, ?>) decoder.readObject();
		decoder.close();

		@SuppressWarnings({ "unchecked", "rawtypes" })
		X509CA ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl((HashMap) ca1Data, 777, CSCA_DN, "test",
				CAConstants.CA_ACTIVE, new Date(), new Date());

		return ca;
	}

}
