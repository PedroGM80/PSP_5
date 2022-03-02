package hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class GeneracionHash {
	public static void main(String[] args) { 
		
		// Cadena de caracteres a calcular el Hash
		String cadena = "Hola Mundo"; 

		MessageDigest md; 
		
		try { 
			// Se transforma la cadena de caracteres en un array de bytes
			byte[] bytes = cadena.getBytes(); 
			// Se obtine un objeto MessageDigest pasándole como parámetro el algoritmo que queremos utilizar
			md = MessageDigest.getInstance("SHA-256");
			// Se le pasan los datos al MessageDigest, mediante el método update
			md.update(bytes); 
			// Se calcula el hash mediante el método digest
			byte[] hash = md.digest();
			System.out.printf("Cadena: [%s]\nHash: [%s]\n.", cadena, valorHexadecimal(hash)); 
		} catch (NoSuchAlgorithmException e) { 
			System.out.println("No disponible algoritmo de hash"); 
		} 
	}

	// Método para pasar el valor a de binario a hexadecimal 
	static String valorHexadecimal(byte[] bytes) { 
		String result = ""; 
		for (byte b : bytes) {
			result += String.format(String.format("%x", b)); 
		} 
		return result; 
	}
}
