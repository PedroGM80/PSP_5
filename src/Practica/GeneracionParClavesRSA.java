package Practica;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class GeneracionParClavesRSA {
	private static final String ALGORITMO_CLAVE_PUBLICA = "RSA";
	private static final int TAM_CLAVE = 1024;
	private static SecureRandom algSeguroGenNumAleat;
	private static final String NOM_FICH_CLAVE_PUBLICA = "clavepublica.der";
	private static final String NOM_FICH_CLAVE_PRIVADA = "claveprivada.pkcs8";

	public static void main(String[] args) {
		try {
			// Creamos un generador de números aleatorios. Al no especificar algoritmo, se selecciona uno al azar
			algSeguroGenNumAleat = SecureRandom.getInstanceStrong();
			// Creamos el generador de llaves con el que podemos obtener ambas claves
			KeyPairGenerator genParClaves = KeyPairGenerator.getInstance(ALGORITMO_CLAVE_PUBLICA);
			genParClaves.initialize(TAM_CLAVE, algSeguroGenNumAleat);
			
			
			// Obtenemos a partir del objeto KeyPair las dos claves
			KeyPair parClaves = genParClaves.generateKeyPair();
			PublicKey clavePublica = parClaves.getPublic();
			PrivateKey clavePrivada = parClaves.getPrivate();

			// Guardamos las claves en un documento cada una
			try (FileOutputStream fosClavePublica = new FileOutputStream(NOM_FICH_CLAVE_PUBLICA)) {
				// Para obtener la clave en vez utilizarse clases transparentes, se utilizan clases codificadoras para generar ficheros
				// binarios en formatos estándares
				// x509EncodedKeySpec es una clase codificadora que va a generar un fichero.der
				X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(clavePublica.getEncoded(),ALGORITMO_CLAVE_PUBLICA);
				fosClavePublica.write(x509EncodedKeySpec.getEncoded());
				// Los valores codificados en basse 64 como texto se muestran en filas de 66 caracteres como 
				// máximo, para mayor legibilidad. Para ello, se añade un retorno de carro cada 76 caracteres
				System.out.printf("Clave pública guardada en formato %s en fichero %s:\n%s\n",
						x509EncodedKeySpec.getFormat(), NOM_FICH_CLAVE_PUBLICA, Base64.getEncoder()
								.encodeToString(x509EncodedKeySpec.getEncoded()).replaceAll("(.{76})", "$1\n"));
			} catch (IOException e) {
				System.out.println("Error de E/S escribiendo clave pública ");
				throw (e);
			}

			try (FileOutputStream fosClavePrivada = new FileOutputStream(NOM_FICH_CLAVE_PRIVADA)) {
				// Para obtener la clave en vez utilizarse clases transparentes, se utilizan clases codificadoras para generar ficheros
				// binarios en formatos estándares
				// pkcs8EncodedKeySpec es una clase codificadora que va a generar un fichero.pkcs8
				PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(clavePrivada.getEncoded(),
						ALGORITMO_CLAVE_PUBLICA);
				fosClavePrivada.write(pkcs8EncodedKeySpec.getEncoded());
				System.out.printf("Clave privada guardada en formato %s en fichero %s:\n%s\n",
						pkcs8EncodedKeySpec.getFormat(), NOM_FICH_CLAVE_PRIVADA, Base64.getEncoder()
								.encodeToString(pkcs8EncodedKeySpec.getEncoded()).replaceAll("(.{76})", "$1\n"));
			} catch (IOException e) {
				System.out.println("Error de E/S escribiendo clave privada ");
				throw (e);
			}
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algoritmo de generación de claves no soportado");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
