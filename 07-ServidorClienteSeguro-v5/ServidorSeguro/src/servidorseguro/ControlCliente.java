/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package servidorseguro;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLSocket;

/**
 *
 * @author link
 */
public class ControlCliente extends Thread {

    private SSLSocket cliente = null;
    DataInputStream controlEntrada = null;
    DataOutputStream controlSalida = null;
    private int contador = 1;
    private boolean salir = false;
    String ID;
    private static final int MAX = 20;
    private Key sessionKey = null;
    private PrivateKey privateKey = null;
    private byte[] sesionCifrada = null;
    private PublicKey publicKey;

    public ControlCliente(SSLSocket cliente) {
        this.cliente = cliente;
        this.contador = 1;
        this.salir = false;
        this.ID = cliente.getInetAddress() + ":" + cliente.getPort();

    }

    @Override
    public void run() {
        // Trabajamos con ella
        if (salir == false) {
            crearFlujosES();
            // Datos de la sesion
            sesion();
            // Tratamos la conexion
            tratarConexion();
            cerrarFlujosES();
        } else {
            this.interrupt(); // Me interrumpo y no trabajo
        }

    }

    private void tratarConexion() {
        // Escuchamos hasta aburrirnos, es decir, hasta que salgamos
        while (!salir) {
            //Recibimos un mensaje
            recibir();
            // Devolvemos una respuesta
            enviar();
            // Aumentamos el contador
            this.contador++;
            // Le indicamos si sale
            if (!salir) {
                salir();

            }
        }
    }

    private void crearFlujosES() {
        try {
            controlEntrada = new DataInputStream(cliente.getInputStream());
            controlSalida = new DataOutputStream(cliente.getOutputStream());
        } catch (IOException ex) {
            System.err.println("ServidorGC->ERROR: crear flujos de entrada y salida " + ex.getMessage());
        }
    }

    private void cerrarFlujosES() {
        try {
            controlEntrada.close();
            controlSalida.close();
        } catch (IOException ex) {
            System.err.println("ServidorGC->ERROR: cerrar flujos de entrada y salida " + ex.getMessage());
        }
    }

    private void salir() {
        if (this.contador >= this.MAX) {
            this.salir = true;
        } else { // No es necssario pero es un ejemplo didáctico y quiero que quede claro
            this.salir = false;
        }
        // Envamos la respuesta
        try {
            System.out.println("ServidorGC->Enviar si salir");
            String salida = String.valueOf(this.salir);
            controlSalida.writeUTF(this.cifrar(salida));
        } catch (IOException ex) {
            System.err.println("ServidorGC->ERROR: al enviar ID de Cliente " + ex.getMessage());
        }
    }

    private void recibir() {
        System.out.println("ServidorGC->Recepción de mensajes");
        try {
            String dato = this.descifrar(this.controlEntrada.readUTF());
            System.out.println("ServidorGC->Mensaje recibido de [" + this.ID + "]: " + dato);
        } catch (IOException ex) {
            System.err.println("ServidorGC->ERROR: al recibir mensaje " + ex.getMessage());
        }
    }

    private void enviar() {
        System.out.println("ServidorGC->Enviado mensaje");
        try {
            String dato = "Mensaje de reespuesta num: " + this.contador;
            this.controlSalida.writeUTF(this.cifrar(dato));
            System.out.println("ServidorGC->Mensaje enviado a [" + this.ID + "]: " + dato);
        } catch (IOException ex) {
            System.err.println("ServidorGC->ERROR: al enviar mensaje " + ex.getMessage());
        }
    }

    private void sesion() {
        // cargamos la clave pública
        cargarClaves();
        // recibimos la clave de sesion
        recibirClave();
        //desciframos la clave
        descifrarClave();
    }

    private void cargarClaves() {
        String fichero = System.getProperty("user.dir") + File.separator + "cert" + File.separator + "AlmacenSSL.jks";
        try {
            FileInputStream fis = new FileInputStream(fichero);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(fis, "1234567".toCharArray());
            fis.close();
            String alias = "claveSSL";
            Key key = keystore.getKey(alias, "1234567".toCharArray());
            if (key instanceof PrivateKey) {
                // Obtenemos el certificado
                Certificate cert = keystore.getCertificate(alias);
                // Obtenemos la clave pública
                this.publicKey = cert.getPublicKey();
                // Casteamos y almacenamos la clave
                this.privateKey = (PrivateKey) key;
            }

        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException | NoSuchAlgorithmException ex) {
            System.err.println("ServidorGC->ERROR: al cargar la clave privada " + ex.getMessage());
        }
    }

    private void recibirClave() {
        System.out.println("ServidorGC->Recibiendo clave de sesión");
        try {
            // leemos la longitid
            int l = this.controlEntrada.readInt();
            byte[] clave = new byte[l];
            this.controlEntrada.read(clave);
            System.out.println("ServidorGC->Clave de sesión recibida de [" + this.ID + "]: " + clave.toString());
            this.sesionCifrada = clave;
        } catch (IOException ex) {
            System.err.println("ServidorGC->ERROR: al recibir mensaje " + ex.getMessage());
        }
    }

    private void descifrarClave() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            this.sessionKey = kg.generateKey();
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(Cipher.UNWRAP_MODE, privateKey);
            this.sessionKey = c.unwrap(this.sesionCifrada, "AES", Cipher.SECRET_KEY);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            System.err.println("ServidorGC->ERROR: al descodificar clave de sesion " + ex.getMessage());
        }
    }

    private String cifrar(String mensaje) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, this.sessionKey);
            byte[] encriptado = c.doFinal(mensaje.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encriptado);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException ex) {
            System.err.println("ServidorGC->ERROR: cifrar mensaje " + ex.getMessage());
        }
        return null;
    }

    private String descifrar(String mensaje) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, this.sessionKey);
            byte[] encriptado = Base64.getDecoder().decode(mensaje);
            byte[] desencriptado = c.doFinal(encriptado);
            // Texto obtenido, igual al original.
            return new String(desencriptado);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
            System.err.println("ServidorGC->ERROR: descifrar mensaje " + ex.getMessage());
        }
        return null;
    }

}
