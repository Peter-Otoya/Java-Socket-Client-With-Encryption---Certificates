import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class SymetricCipher {
	// -------------------------------
	// Atributos
	// -------------------------------

	private SecretKey desKey;
	private String PADDING;

	// -------------------------------
	// Constructor
	// -------------------------------

	public SymetricCipher() {
		PADDING = SecureSocketTcpClient.ALGs + "/ECB/PKCS5Padding";
	}

	// -------------------------------
	// Metodos
	// -------------------------------

	public byte[] cipher(byte[] clearText) {
		byte[] cipheredText;
		try {
			Cipher cipher = Cipher.getInstance(PADDING);
			cipher.init(Cipher.ENCRYPT_MODE, desKey);
			cipheredText = cipher.doFinal(clearText);
			return cipheredText;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}

	public byte[] descifrar(byte[] cipheredText) {
		try {
			Cipher cipher = Cipher.getInstance(PADDING);
			cipher.init(Cipher.DECRYPT_MODE, desKey);
			byte[] clearText = cipher.doFinal(cipheredText);
			return clearText;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}
	
	public void setKey(SecretKey LS) { this.desKey = LS; }
	
	public SecretKey getKey() { return this.desKey; }

}
