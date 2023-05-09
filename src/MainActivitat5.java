import javax.crypto.*;
import java.io.FileOutputStream;
import java.security.*;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Scanner;

public class MainActivitat5 {
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        System.out.println("exercici 1.1.1");
        String misatge = "L'Aitor esta xifrant y desxifrant missatges.";
        KeyPair keyPair = UtilitatsXifrar.randomGenerate(1024);
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] mensajeCifrado = cipher.doFinal(misatge.getBytes());

            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

            // Desciframos el mensaje
            byte[] mensajeDescifrado = cipher.doFinal(mensajeCifrado);
            String mensajeOriginal = new String(mensajeDescifrado,0, mensajeDescifrado.length);

            // Mostramos los resultados
            System.out.println("Mensaje original: " + misatge);
            System.out.println("Mensaje descifrado: " + mensajeOriginal);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
        System.out.println("\n\n\n");


        System.out.println("exercici 1.1.2");
        System.out.println("Introduce el mensaje a cifrar:");
        String mensajescanner = sc.nextLine();
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] mensajeCifrado = cipher.doFinal(mensajescanner.getBytes());

            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

            // Desciframos el mensaje
            byte[] mensajeDescifrado = cipher.doFinal(mensajeCifrado);
            String mensajeOriginal = new String(mensajeDescifrado,0, mensajeDescifrado.length);

            // Mostramos los resultados
            System.out.println("Mensaje original: " + mensajescanner);
            System.out.println("Mensaje descifrado: " + mensajeOriginal);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
        System.out.println("\n\n\n");

        System.out.println("Exercici 1.1.3");
        System.out.println("KEY PUBLIC "+ keyPair.getPublic().getAlgorithm()+" "+ Arrays.toString(keyPair.getPublic().getEncoded()) +" "+keyPair.getPublic().getFormat());
        System.out.println("KEY PRIVAT "+ keyPair.getPrivate().getAlgorithm()+" "+ Arrays.toString(keyPair.getPrivate().getEncoded()) +" "+keyPair.getPrivate().getFormat());

        System.out.println("\n\n\n");
        System.out.println("Exercici 1.2.1");
        KeyStore ks = UtilitatsXifrar.loadKeyStore("/home/aitorarago/.keystore","aitor333");
        System.out.println(
                "1. Tipus de keystore que és (JKS, JCEKS, PKCS12, ...): " + ks.getType() +
                        "\n2. Mida del magatzem (quantes claus hi ha?): " + ks.size() +
                        "\n3. Àlies de totes les claus emmagatzemades: ");

        Enumeration<String> aliases = ks.aliases();
        String alias = null;
        while (aliases.hasMoreElements()) {
            alias = aliases.nextElement();
            System.out.print("  - " + alias);
        }

        System.out.println("4. El certificat d’una de les claus: " + ks.getCertificate(alias)+
                        "\n5. L'algorisme de xifrat d’alguna de les claus: "+ ks.getCertificate(alias).toString());

        System.out.println("\n\n\n");
        System.out.println("Exercici 1.2.2");
        SecretKey skey3 = UtilitatsXifrar.passwordKeyGeneration("12345678",128);
        String s = "aitor333";
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(s.toCharArray());
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(skey3);
        ks.setEntry("mykey2", skEntry ,protParam);
        FileOutputStream out = new FileOutputStream("/home/aitorarago/.keystore");
        ks.store(out,s.toCharArray());
        out.close();
        System.out.println("Nova clau desada al keystore!");

        System.out.println("\n\n\n");
        System.out.println("Exercici 1.3");
        System.out.println("Introduce la ruta al fitchero .cer ");
        String path = sc.nextLine();
        PublicKey publicKey = UtilitatsXifrar.getPublicKey(path);
        System.out.println("KEY PUBLIC :\nAlgoritm:\n"+ publicKey.getAlgorithm()+" \nEncoded:\n"+ Arrays.toString(publicKey.getEncoded()) +" \nFormat:\n"+publicKey.getFormat());

        System.out.println("\n\n\n");
        System.out.println("Exercici 1.4");
        System.out.println("introduce la ruta al keystore");
        String pathh = sc.nextLine();
        System.out.println("introduce el alias: ");
        String aliass = sc.nextLine();
        System.out.println("introduce el password (Keystore): ");
        String pass = sc.nextLine();
        System.out.println("introduce el password (key): ");
        String passk = sc.nextLine();
        PublicKey publicKeyy = UtilitatsXifrar.getPublicKey(UtilitatsXifrar.loadKeyStore(pathh,pass),aliass,passk);
        System.out.println("KEY PUBLIC :\nAlgoritm:\n"+ publicKeyy.getAlgorithm()+" \nEncoded:\n"+ Arrays.toString(publicKey.getEncoded()) +" \nFormat:\n"+publicKey.getFormat());


        System.out.println("\n\n\n");
        System.out.println("Exercici 1.5");
        String mensaje = "ABCDEFGHIJQLMNÖPQRSTUVWXYZ";
        byte[] firma = UtilitatsXifrar.signData(mensaje.getBytes(),keyPair.getPrivate());
        System.out.println("Firma generada: " + Arrays.toString(firma));

        System.out.println("\n\n\n");
        System.out.println("Exercici 1.6");
        System.out.println(UtilitatsXifrar.validateSignature(mensaje.getBytes(),firma,keyPair.getPublic()));


        System.out.println("\n\n\n");
        System.out.println("Exercici 2.2");
        String missatgee = "Aquesta ja es l'ultima practica del cicle de M09";
        byte[][] encrypt = UtilitatsXifrar.encryptWrappedData(missatgee.getBytes(),keyPair.getPublic());

        byte[] desencrypt = UtilitatsXifrar.decryptWrappedData(encrypt,keyPair.getPrivate());
        String s1 = new String(desencrypt,0, desencrypt.length);
        System.out.println(s1);

    }
}
