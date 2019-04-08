import javax.security.auth.x500.X500Principal;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.*;

public class SecureSocketTcpClient extends Thread  {

	//
	// ------------------------------------------
	// Constantes
	// ------------------------------------------

	public final static String ALGs = "AES";
	public final static String ALGa = "RSA";
	public final static String ALGh = "HMACSHA1";
	public final static String direccion = "infracomp.virtual.uniandes.edu.co";
	public final static int puerto = 443;

	// ------------------------------------------
	// Atributos
	// ------------------------------------------

	private KeyPair keyPair;
	private SecretKey secretKey;
	private SymetricCipher symetricCipher;
	private Socket socket;
	private PrintWriter writeStream;
	private BufferedReader readStream;
	private String datos;
	@SuppressWarnings("deprecation")
	private static X509V3CertificateGenerator certGen; 

	// ------------------------------------------
	// Constructor
	// ------------------------------------------

	@SuppressWarnings("deprecation")
	public SecureSocketTcpClient() {
		try {
			// Generacion de la pareja de llaves (K-,K+)
			KeyPairGenerator gen = KeyPairGenerator.getInstance(ALGa);
			gen.initialize(1024);
			keyPair = gen.generateKeyPair();
			
			// Instanciacion generadores de certificado
			certGen =  new X509V3CertificateGenerator();
			Security.addProvider(new BouncyCastleProvider());
			    
			// inicializacion del canal
			socket = new Socket(direccion, puerto);
			readStream = new BufferedReader(new InputStreamReader(
					socket.getInputStream()));
			writeStream = new PrintWriter(socket.getOutputStream(), true);
			
		} catch (Exception e) {
			e.printStackTrace();
		}

		// inicializacion de los cifrador simetrico
		this.symetricCipher = new SymetricCipher(); // <!> Este debe "setearsele"la llave simetrica cuando se obtenga.

		// inicializacion de los datos de envio. Representacion XML de un Album
		// musical.
		setDatos("<Album>\n" + "	<TITLE>Empire Burlesque</TITLE>\n"
				+ "	<ARTIST>Bob Dylan</ARTIST>\n" + "	<COUNTRY>USA</COUNTRY>\n"
				+ "	<COMPANY>Columbia</COMPANY>\n" + "	<PRICE>10.90</PRICE>\n"
				+ "	<YEAR>1985</YEAR>\n" + "</Album>");

	}

	// ------------------------------------------
	// Run method
	// ------------------------------------------

	public void run() {

		String in;
		String status;
		String[] temp;
		try {
			// 1. El cliente inicia la comunicaci�n enviando una solicitud de inicio de sesi�n, a continuaci�n espera un mensaje de confirmaci�n de inicio del servidor.
			writeStream.println("HOLA");
			System.out.println( "Se envio: hola" );
			in = readStream.readLine();
			System.out.println("Se recibio: ACK");
			
			if (!in.equals("ACK"))
				throw new Exception("El servidor no dijo ACKNOWLEDGE");

			// 2. El cliente env�a la lista de algoritmos de cifrado que usar� durante la sesi�n y espera un segundo mensaje del 
			//    servidor confirmando si soporta los algoritmos seleccionados (si no, el servidor corta la comunicaci�n). 
			writeStream.println("ALGORITMOS" + ":" + ALGs + ":" + ALGa + ":"+ ALGh);
			System.out.println( "Se envio: Los algoritmos" );

			in = readStream.readLine();
			System.out.println("Se recibio: el status de confirmacion de los algos");
			temp = in.split(":");
			status = temp[1];
			
			if (!temp[0].equals("STATUS")) {
				throw new Exception("La respuesta del servidor fue "+in);
			}
			if (status.equals("ERROR"))
				throw new Exception("El servidor no soporta los algoritmos y rompio comunicacion");

			// 3. El servidor env�a su certificado digital (CD) para autenticarse con el cliente. El CD debe seguir el est�ndar X509. 
			in = readStream.readLine();
			System.out.println("Se recibio: \"CERTSRV\"");
			
			if (!in.equals("CERTSRV"))
				throw new Exception("Error de formato");

			InputStream inStr = socket.getInputStream();
			byte[] b = new byte[2000];
			inStr.read(b);
			System.out.println("Se recibio : Certificado del srv y el primer byte es : "+b[0]);
			
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cd_srv = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(b));
			PublicKey srvPubKey = cd_srv.getPublicKey(); // obtencion de la llave publica del servidor

			// 4. El cliente env�a su certificado digital (CD) para autenticarse con el servidor. El CD debe seguir el est�ndar X509.
			
			writeStream.println("CERCLNT");
			System.out.println( "Se envio: \"CERCLNT\" " );
			X509Certificate cd_clnt = SecureSocketTcpClient.generarCertificado(this.keyPair.getPrivate(),this.keyPair.getPublic());
			OutputStream outStr = this.socket.getOutputStream();
			outStr.write(cd_clnt.getEncoded());
			outStr.flush();
			System.out.println( "Se envio: El certeificado del cliente" );
			
			// 5. El servidor genera una llave sim�trica (LS) y la env�a al cliente protegida (cifrada). 
			
			in = readStream.readLine();
			System.out.println("Se recibio: la llave secreta");
			temp = in.split(":");
			System.out.println("El servidor dice: "+ in);
			if (!(temp[0]).equals("INIT"))
				throw new Exception("Respuesta del servidor = "+in );

			
			// 6. El cliente descifra el mensaje y obtiene la llave sim�trica que el servidor env�a. Como mecanismo de confirmaci�n 
			//    el cliente env�a la misma llave al servidor, protegida, y espera la confirmaci�n del servidor (OK o ERROR). 
			
			byte[] C_LS_ = BytesMarshaller.destransformar(temp[1]);
			byte[] LS_candidata = AsymetricCipher.descifrar( C_LS_ , keyPair.getPrivate() );
			byte[] secKey_encrypted = AsymetricCipher.cifrar(LS_candidata , srvPubKey);
			
			writeStream.println( "INIT" + ":"+ BytesMarshaller.transformar( secKey_encrypted ) );
			System.out.println( "Se envio: La llave secreta encriptada" );
			
			in = readStream.readLine();
			System.out.println("Se recibio: La confirmacion de la llave");
			temp = in.split(":");
			
			
			if (!temp[0].equals("STATUS")) {
				throw new Exception("No mando el mensaje adecuado. Respuesta del servidor = "+in  );
			}
			else if (temp[1].equals("ERROR")) {
				throw new Exception(
						"El servidor confirmo que la llave secreta recibida, difiere de la enviada");
			}
			else{
				// la llave secreta se confirmo con exito.
				setSecretKey( new SecretKeySpec( LS_candidata, 0,LS_candidata.length, this.ALGs ) );
			}
			
			// 7. El cliente usa la llave sim�trica para enviar la informaci�n protegida.
			
			this.symetricCipher.setKey(secretKey);
			byte[] datosCifrados = this.symetricCipher.cipher( datos.getBytes() );
			writeStream.println( "INFO" + ":"+ BytesMarshaller.transformar( datosCifrados ) );
			System.out.println( "Se envio: Los datos cifrados" );
			
			// 8. Adem�s, el cliente env�a el c�digo hash correspondiente, cifrado con su llave privada (de tal forma que el servidor 
			//    podr� comprobar el origen con la llave p�blica correspondiente). 
			
			byte[] hash = hashSignature(datos.getBytes());
			byte[] cifradoDelHash = AsymetricCipher.cifrar( hash , keyPair.getPrivate() );

			writeStream.println( "INFO" + ":" + BytesMarshaller.transformar(cifradoDelHash) );
			System.out.println( "Se envio: El hash cifrado" );
			
			// 9. El servidor responde (RTA), RTA: OK o ERROR, anunciando el resultado de la transacci�n y la terminaci�n de la comunicaci�n. 
			in = readStream.readLine();
			temp = in.split(":");
			if (!temp[0].equals("INFO")) {
				throw new Exception("Respuesta del servidor = "+in );
			}
			
			byte[] C_rta_ = BytesMarshaller.destransformar(temp[1]) ;
			byte[] rta = this.symetricCipher.descifrar( C_rta_ ) ;
			System.out.println(" \n  Los datos enviados estan : "+  new String(rta) );

			
			
		} catch (Exception e) {
			System.out.println("\n\n>> Error message : "+e.getMessage()+"\n");
			
			e.printStackTrace();
			try {
				writeStream.close();
				readStream.close();
				socket.close();
			} catch (IOException ee) {
				ee.printStackTrace();
			}
		}
		
		try {
			writeStream.close();
			readStream.close();
			socket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		

	}

	// ------------------------------------------
	// Metodos
	// ------------------------------------------



	/**
	 * Crea un certificado X509 Version 3
	 *
	 *            - Pareja de llaves
	 * @return El certificado.
	 * @throws InvalidKeyException
	 * @throws SecurityException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws IllegalStateException
	 * @throws CertificateEncodingException
	 */
	@SuppressWarnings("deprecation")
	public static X509Certificate generarCertificado(PrivateKey priv, PublicKey pub)
			throws InvalidKeyException, SecurityException, SignatureException,CertificateEncodingException,
			IllegalStateException, NoSuchAlgorithmException {

		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal(
				"CN=Certificado : Cliente InfraComp Caso 2"));
		certGen.setNotBefore(new Date());
		certGen.setNotAfter( new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)) );
		certGen.setSubjectDN(new X500Principal(
				"CN=Certificado : Cliente InfraComp Caso 2"));
		certGen.setSignatureAlgorithm("SHA256WithRSA");
		certGen.setPublicKey( pub );

		return certGen.generate( priv );
	}

	/**
	 * Calcula el codigo HMAC, utilizando el algoritmo "ALGh", correspondiente a
	 * un {} de datos
	 * 
	 * @param rawData
	 *            - bytes de los datos a los cuales se les quieren calcular el
	 *            codigo.
	 * @return codigo HMAC en bytes.
	 */
	private byte[] hashSignature(byte[] rawData) {
		try {
			String algoritmo = "Hmac" + ALGh.split("HMAC")[1];
			SecretKeySpec key = new SecretKeySpec(this.secretKey.getEncoded(),
					algoritmo);
			Mac mac = Mac.getInstance(algoritmo);
			mac.init(key);
			byte[] rawHmac = mac.doFinal(rawData);
			return rawHmac;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	
	
	public SecretKey getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(SecretKey lS) {
		secretKey = lS;
	}

	public String getDatos() {
		return datos;
	}

	public void setDatos(String datos) {
		this.datos = datos;
	}

	public KeyPair getKeyPair() {
		return keyPair;
	}

}
