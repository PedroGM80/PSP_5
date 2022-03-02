package Ejercicios;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/*
. Crea un método que realice el descifrado de un fichero cifrado mediante el algoritmo
DES. Como parámetro se deben especificar el nombre de un fichero que contiene la clave y
fichero donde se encuentra el mensaje cifrado. El mensaje descifrado se deberá guardar en
un fichero de nombre mensaje.desencript.

 */
public class E2 {
    private static final String ALGORITMO_CLAVE_SIMETRICA = "DES"; // 3DES


    public static void descifraMsnDes(String nombrefichclave, String nombrefichMsnCifrado) throws NoSuchAlgorithmException {
        String FICH_CLAVE = nombrefichclave;


        String mensajeCifrado = "";
        try (InputStream in = new FileInputStream(nombrefichMsnCifrado);
             BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String str = null;
            StringBuilder sb = new StringBuilder(8192);
            while ((str = r.readLine()) != null) {
                sb.append(str);
            }
            mensajeCifrado = sb.toString();
        } catch (IOException ioe) {
            ioe.printStackTrace();
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
            cifrado.init(Cipher.DECRYPT_MODE, clave);

            //Desciframos el mensaje
            String mensajeDescifrado = new String(cifrado.doFinal(mensajeCifrado.getBytes()));
            System.out.println(mensajeDescifrado);
            FileOutputStream fsalida = new FileOutputStream("mensaje.desencript");
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
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        descifraMsnDes("miclave.raw","mensaje.encript");
    }

}

