package Practica;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import java.util.regex.Pattern;

/*
Combina los dos ejercicios para encriptar y desencriptar un fichero con DES.
 Hay que crear un programa que encripte o desencripte dependiendo del valor de un nuevo parámetro de
línea de comandos. Con -e se encriptará, y con -d se desencriptará.

El programa se ejecutará desde la consola.

En el caso de usar -e se deberán pasar al programa otros dos parámetros: el nombre/ruta
del fichero que contiene la clave y el nombre/ruta del fichero cuyos contenidos se quieren
cifrar.

En caso de usar -d se deberán pasar al programa otros dos parámetros: el nombre del
fichero que contiene la clave y el nombre/ruta del fichero a descifrar.

Además, hay que añadir un mecanismo de control de integridad, que consistirá en que,
antes de encriptar, se añade al principio del fichero un hash SHA-1 de los contenidos del
fichero.

 Después de descifrar el fichero, se debe comparar el valor de hash que viene al
principio con el calculado para el resto del fichero.

 Si no coinciden, debe mostrarse un mensaje de error y debe borrarse el fichero desencriptado que se acaba de crear.
Nota: Para el cifrado, en vez de pasarle un mensaje a cifrar al programa, se pasará un
fichero que contiene el mensaje a cifrar.
 */
public class Practica {
    private static byte[] SHA1 = null;
    private static final String ALGORITMO_CLAVE_SIMETRICA = "DESede"; // 3DES
    private static final String FICH_CLAVE = "clave.raw";


    public static byte[] SHA1(String x) throws NoSuchAlgorithmException {

        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        SHA1 = sha1.digest((x).getBytes());
        return SHA1;
    }

    public static void encripta(String rutaClave, String rutaContenido) throws NoSuchAlgorithmException {
        String datosFichero = "";
        try {
            File myObj = new File(rutaContenido);
            Scanner myReader = new Scanner(myObj);
            while (myReader.hasNextLine()) {
                String data = myReader.nextLine();
                datosFichero += data;
            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        String prefijoSha = SHA1(datosFichero).toString();
       // datosFichero = prefijoSha + datosFichero;
        String datosClave = "";
        try {
            File myObj = new File(rutaClave);
            Scanner myReader = new Scanner(myObj);
            while (myReader.hasNextLine()) {
                String data = myReader.nextLine();
                datosClave += data;
            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }


        // Nombre del fichero a cifrar
        //String mensaje = "Hola Mundo";

        // Obtenemos la clave leyendo el fichero donde se encuentra
        byte valorClave[];
        try (FileInputStream sClave = new FileInputStream(rutaClave)) {
            valorClave = sClave.readAllBytes();
        } catch (FileNotFoundException e) {
            System.out.printf("ERROR: no existe fichero de clave %s\n.", rutaClave);
            return;
        } catch (IOException e) {
            System.out.printf("ERROR: de E/S leyendo clave de fichero %s\n.", rutaClave);
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
            String mensajeCifrado = new String(cifrado.doFinal(datosClave.getBytes()));
            System.out.println(mensajeCifrado);
            try {
                FileWriter myWriter = new FileWriter(rutaContenido);
                myWriter.write(mensajeCifrado);
                myWriter.close();
                System.out.println("Successfully wrote to the file.");
            } catch (IOException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
            }

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

    public static void desencripta(String rutaClave, String rutaContenido) throws IOException, NoSuchAlgorithmException {

        // Nombre del fichero a descifrar
        // String mensajeCifrado = "nðØn7ÎpãV\"…p2NÂ";
        String datosFichero = null;
        try {
            File myObj = new File(rutaContenido);
            Scanner myReader = new Scanner(myObj);
            while (myReader.hasNextLine()) {
                String data = myReader.nextLine();
                datosFichero += data;
            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        //String prefijoSha = SHA1(datosFichero).toString();
        //datosFichero.replaceAll(prefijoSha, "");
        String datosClave = "";
        try {
            File myObj = new File(rutaClave);
            Scanner myReader = new Scanner(myObj);
            while (myReader.hasNextLine()) {
                String data = myReader.nextLine();
                datosClave += data;
            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        // Obtenemos la clave leyendo el fichero donde se encuentra
        byte valorClave[];
        try (FileInputStream sClave = new FileInputStream(rutaClave)) {
            valorClave = sClave.readAllBytes();
        } catch (FileNotFoundException e) {
            System.out.printf("ERROR: no existe fichero de clave %s\n.", rutaClave);
            return;
        } catch (IOException e) {
            System.out.printf("ERROR: de E/S leyendo clave de fichero %s\n.", rutaClave);
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
            String mensajeDescifrado = new String(cifrado.doFinal(datosFichero.getBytes()));
            System.out.println(mensajeDescifrado);

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

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        System.out.println("aqui1");
        String entrada = args.toString();
        System.out.println(entrada);
        if (args[0].equals("-e")) {

            String rutaDatos = args[1];
            String rutaClave = args[2];
            encripta(rutaDatos, rutaClave);

        } else if (args[0].equals("-d")) {

            String rutaDatos = args[1];
            String rutaClave = args[2];
            desencripta(rutaDatos, rutaClave);
        }
    }
}
