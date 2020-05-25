package util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.util.Properties;

import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.FileTools;
import org.cesecore.util.StringTools;

public class CryptoUtil {

	public static KeyPair genTestKeyPair(String algName) throws InvalidAlgorithmParameterException {
		if (algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410)) {
			final String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("gost3410", "B");
			if (keyspec != null) {
				return KeyTools.genKeys(keyspec, AlgorithmConstants.KEYALGORITHM_ECGOST3410);
			} else {
				return null;
			}
		} else if (algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145)) {
			final String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("dstu4145", "233");
			if (keyspec != null) {
				return KeyTools.genKeys(keyspec, AlgorithmConstants.KEYALGORITHM_DSTU4145);
			} else {
				return null;
			}
		} else if (algName.equals(AlgorithmConstants.SIGALG_SHA1_WITH_DSA)) {
			return KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_DSA);
		} else if (algName.contains("ECDSA")) {
			return KeyTools.genKeys("brainpoolp224r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
		} else {
			return KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
		}
	}

	public static String getTestKeySpec(String algName) {
		if (algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410)) {
			return CesecoreConfiguration.getExtraAlgSubAlgName("gost3410", "B");
		} else if (algName.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145)) {
			return CesecoreConfiguration.getExtraAlgSubAlgName("dstu4145", "233");
		} else if (algName.equals(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA)) {
			return "brainpoolp224r1";
		} else if (algName.equals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA)) {
			return "prime256v1";
		} else if (algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1)) {
			return "2048"; // RSA-PSS required at least 2014 bits
		} else if (algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1)) {
			return "2048"; // RSA-PSS required at least 2014 bits
		} else if (algName.equalsIgnoreCase(AlgorithmConstants.SIGALG_SHA1_WITH_DSA)) {
			return "DSA1024";
		} else {
			return "1024"; // Assume RSA
		}
	}

	public static void saveCryptoToken(CryptoToken cryptoToken, String propFileName, String tokenFileName)
			throws FileNotFoundException, IOException {
		cryptoToken.getProperties().store(new FileOutputStream(new File(propFileName)), "Crypto Token");
		FileUtil.saveFile(tokenFileName, cryptoToken.getTokenData());
	}

	public static CryptoToken loadCSCACryptoToken(String propFileName, String tokenFileName, String password) throws IOException, NoSuchSlotException, CryptoTokenOfflineException,
			CryptoTokenAuthenticationFailedException {
		byte[] data = FileTools.readFiletoBuffer(tokenFileName);
		Properties prop = new Properties();
		prop.load(new FileInputStream(new File(propFileName)));

		CryptoToken cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), prop, data, 17,
				"Another cryptoToken");
		cryptoToken.activate(password.toCharArray());

		return cryptoToken;
	}

	public static CAToken createCAToken(CryptoToken cryptoToken, String sigAlg)
			throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {

		cryptoToken.generateKeyPair(CryptoUtil.getTestKeySpec(sigAlg), CAToken.SOFTPRIVATESIGNKEYALIAS);
		cryptoToken.generateKeyPair(CryptoUtil.getTestKeySpec(sigAlg), CAToken.SOFTPRIVATEDECKEYALIAS);

		// Create CAToken
		Properties caTokenProperties = new Properties();
		caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
		caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
		caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);

		// only for csca
		caTokenProperties.setProperty(CryptoToken.EXPLICIT_ECC_PUBLICKEY_PARAMETERS, Boolean.TRUE.toString());

		CAToken caToken = new CAToken(cryptoToken.getId(), caTokenProperties);

		// Set key sequence so that next sequence will be 00001 (this is the
		// default though so not really needed here)
		caToken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
		caToken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
		caToken.setSignatureAlgorithm(sigAlg);
		caToken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);

		return caToken;
	}

	public static CryptoToken createCryptoToken(String password) throws IOException {
		final Properties cryptoTokenProperties = new Properties();
		cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, password);
		CryptoToken cryptoToken = null;
		try {
			cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), cryptoTokenProperties,
					null, 17, "CryptoToken's name");
		} catch (NoSuchSlotException e) {
			throw new IllegalStateException("Attempted to find a slot for a soft crypto token. This should not happen.",
					e);
		}

		return cryptoToken;
	}
}
