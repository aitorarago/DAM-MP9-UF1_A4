import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class UtilitatsXifrar {

    //Activitat 4
    public static SecretKey keygenKeyGeneration(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }
    public static SecretKey passwordKeyGeneration(String text, int keySize){
        SecretKey sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                byte[] data = text.getBytes("UTF-8");
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash, keySize/8);
                sKey = new SecretKeySpec(key, "AES");
            } catch (Exception ex) {
                System.err.println("Error generant la clau:" + ex);
            }
        }
        return sKey;
    }

    public static byte[] encryptData(byte[] data, SecretKey key){
        System.out.println("encriyptant...");
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return encryptedData;
    }

    public static byte[] decryptData(byte[] data, SecretKey key){
        System.out.println("desencryptant...");
        byte[] encryptedData = data;
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.out.println("Error al desencryptar les dades, Password Incorrecte.");
        }
        return encryptedData;
    }


    //Activitat 5

    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public static KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        File f = new File (ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream (f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }

    public static byte[] signData(byte[] data, PrivateKey priv) {
        byte[] signature = null;

        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(priv);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception ex) {
            System.err.println("Error signant les dades: " + ex);
        }
        return signature;
    }
    public static boolean validateSignature(byte[] data, byte[] signature, PublicKey pub) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(pub);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }

    public static PublicKey getPublicKey(String fitxer) throws CertificateException, IOException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(fitxer);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        fis.close();
        return cert.getPublicKey();

    }
    public static PublicKey getPublicKey(KeyStore ks, String alias, String pwMyKey) throws Exception {
        char[] password = pwMyKey.toCharArray();
        if (!ks.containsAlias(alias)) {
            throw new Exception("Alias not found");
        }
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        if (cert == null) {
            throw new Exception("Certificate not found");
        }
        return cert.getPublicKey();

    }

    public static byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
        byte[][] encWrappedData = new byte[2][];
        try {
            //GENERACIÓ DE LES CLAUS
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            //GENERA LA CLAU SECRETA
            SecretKey sKey = kgen.generateKey();
            //ALGORITME DE XIFRAT SIMÈTRIC
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            //XIFRA LES DADES
            byte[] encMsg = cipher.doFinal(data);
            //ALGORITME DE XIFRAT ASIMÈTRIC
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, pub);
            byte[] encKey = cipher.wrap(sKey);
            //DADES XIFRADES
            encWrappedData[0] = encMsg;
            //CLAU XIFRADA
            encWrappedData[1] = encKey;
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return encWrappedData;
    }

    public static byte[] decryptWrappedData(byte[][] encWrappedData, PrivateKey priv) {
        //encWrappedData[0] misatge xifrat
        //encWrappedData[1] clau xifrada
        byte[] decData = null;
        try {
            //ALGORITME DE XIFRAT ASIMÈTRIC
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.UNWRAP_MODE, priv);
            //CLAU SIMÈTRICA
            Key sKey = cipher.unwrap(encWrappedData[1], "AES", Cipher.SECRET_KEY);
            //ALGORITME DE XIFRAT SIMÈTRIC
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            // OBTENCIÓ DEL MISSATGE DESENCRYPTAT
            decData = cipher.doFinal(encWrappedData[0]);
        } catch (Exception ex) {
            System.err.println("Ha succeït un error desxifrant: " + ex);
        }
        return decData;
    }


}
