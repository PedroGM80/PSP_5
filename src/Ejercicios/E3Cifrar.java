package Ejercicios;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class E3Cifrar {


    private static final String ALGORITMO_CLAVE = "RSA";
    private static final String FICH_CLAVE_PUB = "clavepublica.der";
    private static final String NOM_FICH_CLAVE_PRIVADA = "claveprivada.pkcs8";

    public static void main(String[] args) {

        String cadenaEnClaro = "Hola Mundo";

        // variable para almacenar la clave p�blica
        byte clavePubCodif[];
        // Guardamos en dicha variable el contenido del fichero con la clave p�blica
        try (FileInputStream sClavePub = new FileInputStream(NOM_FICH_CLAVE_PRIVADA)) {
            clavePubCodif = sClavePub.readAllBytes();
        } catch (FileNotFoundException e) {
            System.out.printf("ERROR: no existe fichero de clave p�blica %s\n.", NOM_FICH_CLAVE_PRIVADA);
            return;
        } catch (IOException e) {
            System.out.printf("ERROR: de E/ S leyendo clave de chero %s\n.", NOM_FICH_CLAVE_PRIVADA);
            return;
        }

        KeyFactory keyFactory;
        try {
            // A partir de KeyFactory obtenemos la clave p�blica opaca a partir de la transparente
            keyFactory = KeyFactory.getInstance(ALGORITMO_CLAVE);
            //X509EncodedKeySpec  = new X509EncodedKeySpec);
            PKCS8EncodedKeySpec publicKeySpec =new PKCS8EncodedKeySpec(clavePubCodif);
            PrivateKey clavePrivada = keyFactory.generatePrivate(publicKeySpec);

            // Transformamos el mensaje en claro en un array de bytes
            byte[] mensajeEnClaro = cadenaEnClaro.getBytes("UTF-8");
            Cipher cifrado = Cipher.getInstance(ALGORITMO_CLAVE);
            // Comienza el cifrado
            cifrado.init(Cipher.ENCRYPT_MODE, clavePrivada);
            byte[] mensajeCifrado = cifrado.doFinal(mensajeEnClaro);
            System.out.printf("Texto cifrado codif. en base 64 como texto:\n%s\n", Base64.getEncoder().encodeToString(mensajeCifrado));

        } catch (NoSuchAlgorithmException e) {
            System.out.printf("ERROR: no existe algoritmo de cifrado %s.\n.", ALGORITMO_CLAVE);
        } catch (InvalidKeySpecException e) {
            System.out.println("ERROR: especificaci�n de clave no v�lida.");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.out.println("Clave no v�lida.");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.out.println("Tama�o de bloque no v�lido.");
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            System.out.println("Excepci�n con relleno.");
            e.printStackTrace();
        } catch (BadPaddingException e) {
            System.out.println("Excepci�n con relleno.");
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            System.out.println("ERROR: codificaci�n de caracteres UTF-8 no soportada.");
        }
    }


}
