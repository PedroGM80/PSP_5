package Ejercicios;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/*
1. Crea un método que realice el cifrado de un MENSAJE mediante el algoritmo DES. Como
parámetros se deben especificar el nombre del fichero que contiene la clave y el mensaje a
cifrar. El mensaje cifrado se deberá guardar en un fichero de nombre mensaje.encript
 */
public class E1 {

    private static final String ALGORITMO_CLAVE_SIMETRICA = "DES"; // DES
    private static final String ALGORITMO_CLAVE_PUBLICA = "RSA";
    private static final int TAM_CLAVE = 1024;
    private static SecureRandom algSeguroGenNumAleat;

    public static void cifraMsnDes(String nombrefichclave, String msn) throws NoSuchAlgorithmException {
        String FICH_CLAVE = nombrefichclave + ".raw";

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
        try (FileOutputStream fosClavePublica = new FileOutputStream(FICH_CLAVE)) {
            // Para obtener la clave en vez utilizarse clases transparentes, se utilizan clases codificadoras para generar ficheros
            // binarios en formatos estándares
            // x509EncodedKeySpec es una clase codificadora que va a generar un fichero.der
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(clavePublica.getEncoded(), ALGORITMO_CLAVE_PUBLICA);
            fosClavePublica.write(x509EncodedKeySpec.getEncoded());
            // Los valores codificados en basse 64 como texto se muestran en filas de 66 caracteres como
            // máximo, para mayor legibilidad. Para ello, se añade un retorno de carro cada 76 caracteres
            System.out.printf("Clave pública guardada en formato %s en fichero %s:\n%s\n",
                    x509EncodedKeySpec.getFormat(), nombrefichclave, Base64.getEncoder()
                            .encodeToString(x509EncodedKeySpec.getEncoded()).replaceAll("(.{76})", "$1\n"));
        } catch (IOException e) {
            System.out.println("Error de E/S escribiendo clave pública ");
            try {
                throw (e);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }





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
            String mensajeCifrado = new String(cifrado.doFinal(msn.getBytes()));
            System.out.println(mensajeCifrado);
            FileWriter fw = new FileWriter("mensaje.encript");
            fw.write(mensajeCifrado);
            fw.close();

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
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        cifraMsnDes("mifichclave", "hola psp");
    }
}
