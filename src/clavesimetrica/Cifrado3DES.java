package clavesimetrica;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Cifrado3DES {
	private static final String ALGORITMO_CLAVE_SIMETRICA = "DESede"; // 3DES
	private static final String FICH_CLAVE = "clave.raw";

	public static void main(String[] args) {

		// Nombre del fichero a cifrar
		String mensaje = "Hola Mundo";

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
			// partir de ésta, generemos una clave opaca
			SecretKeySpec keySpec = new SecretKeySpec(valorClave, ALGORITMO_CLAVE_SIMETRICA);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITMO_CLAVE_SIMETRICA);
			SecretKey clave = keyFactory.generateSecret(keySpec);

			// Creamos un objeto Cipher y realizamos la encriptación con la clave privada
			Cipher cifrado = Cipher.getInstance(ALGORITMO_CLAVE_SIMETRICA);
			cifrado.init(Cipher.ENCRYPT_MODE, clave);
			// A partir de aquí todo lo que se escriba estará cifrado usando la clave
			String mensajeCifrado=new String(cifrado.doFinal(mensaje.getBytes()));
			System.out.println(mensajeCifrado);
					
			
		} catch (NoSuchAlgorithmException e) {
			System.out.printf("No existe algoritmo de cifrado %s.\n", ALGORITMO_CLAVE_SIMETRICA);
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			System.out.println("Especificación de clave no válida.");
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println("Clave no válida.");
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			System.out.println("Tamaño de bloque no válido.");
			e.printStackTrace();
		} catch (BadPaddingException e) {
			System.out.println("Excepción con relleno.");
			e.printStackTrace();
		}
	}
}
