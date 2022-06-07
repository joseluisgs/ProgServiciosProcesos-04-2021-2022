/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package clienteseguro;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSession;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.io.File;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author link
 */
public class Cliente {

    private final int PUERTO = 6666;
    //private InetAddress direccion;
    private String direccion;
    private SSLSocket servidor;
    private SSLSocketFactory clientFactory;
    private boolean salir = false;
    DataInputStream datoEntrada = null;
    DataOutputStream datoSalida = null;
    private static final int ESPERAR = 1000;
    private Key sessionKey;
    private PublicKey publicKey;
    private byte[] sesionCifrada;

    public void iniciar() {
        // Antes de nada compruebo la direccion
        comprobar();
        // Nos conectamos
        conectar();
        //
        imprimirSesion();
        //enviar Clave()
        sesion();
        // Procesamos
        procesar();
        //Cerramos
        cerrar();
    }

    private void comprobar() {
        try {
        // Consigo la dirección (ojo está puesta la de mi ma´uina virtual)
        direccion = InetAddress.getLocalHost().getHostAddress(); //"192.168.169.2"; //InetAddress. //InetAddress.getLocalHost(); // dirección local (localhost)
        } catch (UnknownHostException ex) {
               System.err.println("Cliente->ERROR: No encuetra dirección del servidor");
            System.exit(-1);
        }
    }

    private void conectar() {
        try {
            // De donde saco los datos
            String fichero = System.getProperty("user.dir") + File.separator + "cert" + File.separator + "UsuarioAlmacenSSL.jks";
            System.setProperty("javax.net.ssl.trustStore", fichero);
            System.setProperty("javax.net.ssl.trustStorePassword", "0987654");
            // Me conecto
            this.clientFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            this.servidor = (SSLSocket) clientFactory.createSocket(this.direccion, this.PUERTO);
            datoEntrada = new DataInputStream(servidor.getInputStream());
            datoSalida = new DataOutputStream(servidor.getOutputStream());
            System.out.println("Cliente->Conectado al servidor...");
        } catch (IOException ex) {
            System.err.println("Cliente->ERROR: No se puede conectar");
            System.exit(-1);
        }
    }

    private void cerrar() {
        try {
            // Me desconecto
            servidor.close();
            datoEntrada.close();
            datoSalida.close();
            System.out.println("Cliente->Desconectado");
        } catch (IOException ex) {
            System.err.println("Cliente->ERROR: No se puede conectar");
            System.exit(-1);
        }
    }

    private void procesar() {
        // Ciclamos hasta que salgamos
        // Escuchamos hasta aburrirnos, es decir, hasta que salgamos
        while (!salir) {
            //Envaimos el mensaje
            enviar();
            // recibimos la respuesta
            recibir();
            // vemos si salimos
            salir();
            // esperamos
            esperar();
        }

    }

    private void enviar() {
        System.out.println("Cliente->Enviado mensaje");
        try {
            String dato = "Mensaje: " + Instant.now().getEpochSecond();
            this.datoSalida.writeUTF(this.cifrar(dato));
            System.out.println("Cliente->Mensaje enviado a Servidor: " + dato);
        } catch (IOException ex) {
            System.err.println("Cliente->ERROR: al enviar mensaje " + ex.getMessage());
        }
    }

    private void recibir() {
        try {
            System.out.println("Cliente->Recepción de mensajes");
            String dato = this.descifrar(this.datoEntrada.readUTF());
            System.out.println("Cliente->Mensaje recibido: " + dato);
        } catch (IOException ex) {
            System.err.println("Cliente->ERROR: al recibir mensaje " + ex.getMessage());
        }
    }

    private void salir() {
        try {
            System.out.println("Cliente->¿Salir?");
            this.salir = Boolean.parseBoolean(this.descifrar(this.datoEntrada.readUTF()));
            System.out.println("Cliente->Salir: " + this.salir);
        } catch (IOException ex) {
            System.err.println("Cliente->ERROR: al recibir salir " + ex.getMessage());
        }
    }

    private void esperar() {
        try {
            Thread.sleep(this.ESPERAR);
        } catch (InterruptedException ex) {
            System.err.println("Cliente->ERROR: al esperar " + ex.getMessage());
        }
    }

    private void sesion() {
        // Generamos la clave de sesion
        claveAES();
        //Recibimos la clave pública
        cargarClave();
        // Ciframos la clave de sesion
        cifrarClave();
        //Enviamos la clave
        enviarClave();

    }

    private void claveAES() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            this.sessionKey = kg.generateKey();
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Cliente->ERROR: al generar la clave de sesion " + ex.getMessage());
        }
    }

    private void cifrarClave() {
        try {
            //se encripta la clave secreta con la clave pública
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(Cipher.WRAP_MODE, this.publicKey);
            this.sesionCifrada = c.wrap(this.sessionKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException ex) {
            System.err.println("Cliente->ERROR: al cifrar la clave de sesion " + ex.getMessage());
        }
    }

    private void enviarClave() {
        // la pasamos cifrada pero como Code64 para que vaya como un string
        byte[] clave = this.sesionCifrada;
        System.out.println("Cliente->Enviado clave de sesion");
        try {
            // Mandamos longitud y clave
            this.datoSalida.writeInt(clave.length);
            this.datoSalida.write(clave);
            System.out.println("Cliente->Clave de sesion enviada " + clave.toString());
        } catch (IOException ex) {
            System.err.println("Cliente->ERROR: al enviar clave " + ex.getMessage());
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

    private void cargarClave() {
        String fichero = System.getProperty("user.dir") + File.separator + "cert" + File.separator + "UsuarioAlmacenSSL.jks";
        try {
            FileInputStream fis = new FileInputStream(fichero);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(fis, "0987654".toCharArray());
            fis.close();
            String alias = "claveSSL";
            Key key = keystore.getKey(alias, "0987654".toCharArray());
            // Obtenemos el certificado
            Certificate cert = keystore.getCertificate(alias);
            // Obtenemos la clave pública
            this.publicKey = cert.getPublicKey();

        } catch (NoSuchAlgorithmException | IOException ex) {
            System.err.println("Cliente->ERROR: al recibir clave pública " + ex.getMessage());
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void imprimirSesion() {
        try {
            SSLSession sesion = ((SSLSocket) this.servidor).getSession();
            System.out.println("Servidor: " + sesion.getPeerHost());
            System.out.println("Cifrado: " + sesion.getCipherSuite());
            System.out.println("Protocolo: " + sesion.getProtocol());
            System.out.println("IDentificador:" + new BigInteger(sesion.getId()));
            System.out.println("Creación de la sesión: " + sesion.getCreationTime());
            X509Certificate certificado = (X509Certificate) sesion.getPeerCertificates()[0];
            System.out.println("Propietario : " + certificado.getSubjectDN());
            System.out.println("Algoritmo: " + certificado.getSigAlgName());
            System.out.println("Tipo: " + certificado.getType());
            System.out.println("Emisor: " + certificado.getIssuerDN());
            System.out.println("Número Serie: " + certificado.getSerialNumber());
        } catch (SSLPeerUnverifiedException ex) {
            System.err.println("Cliente->ERROR: al leer información del certificado " + ex.getMessage());
        }
    }

}
