import java.security.Key;

import javax.crypto.Cipher;

public class AsymetricCipher {

	// -------------------------------
	// Atributos
	// -------------------------------
	private final static String ALGORITMO = SecureSocketTcpClient.ALGa;

	// -------------------------------
	// Metodos
	// -------------------------------

	public static byte[] cifrar(byte[] clearText, Key k) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.ENCRYPT_MODE, k );
			byte[] cipheredText = cipher.doFinal(clearText);
			return cipheredText;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}

	public static byte[] descifrar(byte[] cipheredText, Key k) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.DECRYPT_MODE, k);
			byte[] clearText = cipher.doFinal(cipheredText);
			return clearText;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}

	
}
