package clavesimetrica;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

public class Descifrado3DS {
	private static final String ALGORITMO_CLAVE_SIMETRICA = "DESede"; // 3DES
	private static final String FICH_CLAVE = "clave.raw";

	public static void main(String[] args) {
		// Nombre del fichero a descifrar
		String mensajeCifrado = "n��n7�p�V\"�p2N�";

		// Obtenemos la clave leyendo el fichero donde se encuentra
		byte valorClave[];
		try (FileInputStream sClave = new FileInputStream(FICH_CLAVE)) {
			valorClave = sClave.readAllBytes();
		} catch (FileNotFoundException e) {
			System.out.printf("ERROR: no existe fichero de clave %s\n.", FICH_CLAVE);
			return;
		} catch (IOException e) {
			System.out.printf("ERROR: de E/S leyendo clave de fichero %s\n.", FICH_CLAVE);
			return;
		}

		try {
			// Obtenemos una clave transparente a partir de la clave ya generada, y luego, a
			// partir de �sta, generemos una clave opaca
			SecretKeySpec keySpec = new SecretKeySpec(valorClave, ALGORITMO_CLAVE_SIMETRICA);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITMO_CLAVE_SIMETRICA);
			SecretKey clave = keyFactory.generateSecret(keySpec);
			
			// Creamos un objeto Cipher y realizamos la encriptaci�n con la clave privada
			Cipher cifrado = Cipher.getInstance(ALGORITMO_CLAVE_SIMETRICA);
			cifrado.init(Cipher.DECRYPT_MODE, clave);

			//Desciframos el mensaje
			String mensajeDescifrado=new String(cifrado.doFinal(mensajeCifrado.getBytes()));
			System.out.println(mensajeDescifrado);
			
		} catch (NoSuchAlgorithmException e) {
			System.out.printf("No existe algoritmo de cifrado %s.\n", ALGORITMO_CLAVE_SIMETRICA);
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			System.out.println("Especificaci�n de clave no v�lida.");
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println("Clave no v�lida.");
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			System.out.println("Tama�o de bloque no v�lido.");
			e.printStackTrace();
		} catch (BadPaddingException e) {
			System.out.println("Excepci�n con relleno.");
			e.printStackTrace();
		}
	}
	
}
