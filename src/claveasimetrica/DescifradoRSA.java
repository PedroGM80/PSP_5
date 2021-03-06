package claveasimetrica;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class DescifradoRSA {
	private static final String ALGORITMO_CLAVE_PUB="RSA";
	private static final String FICH_CLAVE_PRIV="claveprivada.pkcs8";

	public static void main(String[] args) { 

		String textoCifrado = "pp2N/v8paepXKLMht4WMNPvAous9zPSZbI96gpBcmwi5bzjcQg4zXrsiArNFIZ/Ip7W2mykuzz7a3hMBBIBMX5VeFXaawl5Uok3BsP+DaVdHbVmKzEkT1LrXN4xXUiU/XM7QNpK4qBeTOVlIBXFg8KB5GNHZrlUNI3c/8AvPC0M=";
		// Variable que representa a la clave privada
		byte clavePrivCodif[]; 
		
		// Leemos el contenido de la clave privada
		try (FileInputStream sClavePriv = new FileInputStream(FICH_CLAVE_PRIV)) { 
			clavePrivCodif = sClavePriv.readAllBytes(); 
		} catch (FileNotFoundException e) { 
			System.out.printf( "ERROR: no existe fichero de clave privada %s\n.", FICH_CLAVE_PRIV); 
			return; 
		} catch (IOException e) {
			System.out.printf("ERROR: de E/ S leyendo clave de fichero %s\n.", FICH_CLAVE_PRIV); 
			return; 
		} 
		
		KeyFactory keyFactory; 
		try { 
			// A partir de KeyFactory obtenemos la clave privada opaca a partir de la transparente
			keyFactory = KeyFactory.getInstance(ALGORITMO_CLAVE_PUB); 
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(clavePrivCodif); 
			PrivateKey clavePrivada = keyFactory.generatePrivate(privateKeySpec); 
			
			byte[] mensajeCifrado = Base64.getDecoder().decode(textoCifrado);
			
			Cipher cifrado = Cipher.getInstance(ALGORITMO_CLAVE_PUB); 
			cifrado.init(Cipher.DECRYPT_MODE, clavePrivada); 
			byte[] mensajeDescifrado = cifrado.doFinal(mensajeCifrado); 
			System.out.printf("Texto descifrado: \n%s\n",new String(mensajeDescifrado,"UTF-8")); 
		} catch (NoSuchAlgorithmException e) { 
			System.out.printf("ERROR: no existe algoritmo de cifrado %s.\n.", ALGORITMO_CLAVE_PUB); 
		} catch (InvalidKeySpecException e) { 
			System.out.println("ERROR: especificaci?n de clave no v?lida."); 
			e.printStackTrace(); 
		} catch (InvalidKeyException e) {
			System.out.println("Clave no v?lida."); 
			e.printStackTrace(); 
		} catch (IllegalBlockSizeException e) { 
			System.out.println("Tama?o de bloque no v?lido."); 
			e.printStackTrace(); 
		} catch (NoSuchPaddingException e) { 
			System.out.println("Excepci?n con relleno.");
			e.printStackTrace(); 
		} catch (BadPaddingException e) { 
			System.out.println("Excepci?n con relleno."); 
			e.printStackTrace(); 
		} catch (UnsupportedEncodingException e) { 
			System.out.println("ERROR: codificaci?n de caracteres UTF-8 no soportada."); 
		} 
	}
}