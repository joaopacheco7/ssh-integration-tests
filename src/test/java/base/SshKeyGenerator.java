package base;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * Class responsible for creating temporary pair of public & private keys.
 */
public class SshKeyGenerator {

	public TempKeyPair createTempKeys() {
		try {
			// Adds the Bouncy Castle provider
			Security.addProvider(new BouncyCastleProvider());

			// Generates the key pair
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			KeyPair pair = keyGen.generateKeyPair();

			// Writes the public key to a temp file
			Path publicKey = writeToTempFile(pair.getPublic(), "public_key");
			System.out.println(String.format("Temporary Public Key created: %s", publicKey));

			// Writes the private key to a temp file
			Path privateKey = writeToTempFile(pair.getPrivate(), "private_key");
			System.out.println(String.format("Temporary Private Key created: %s", privateKey));

			return new TempKeyPair(publicKey, privateKey);

		} catch (NoSuchAlgorithmException | IOException e) {
			e.printStackTrace();
			throw new IllegalStateException(e);
		}
	}


	/**
	 * Writes a key to a temporary file in PEM format.
	 */
	private Path writeToTempFile(Key key, String filename) throws IOException {
		Path tempKey = Files.createTempFile(filename, ".pem");
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(tempKey.toFile()))) {
			pemWriter.writeObject(key);
		}
		return tempKey;
	}


	public record TempKeyPair(Path publicKey, Path privateKey) {

		@Override
		public String toString() {
			return "KeyPair{" + "publicKey=" + publicKey + ", privateKey=" + privateKey + '}';
		}
	}
}
