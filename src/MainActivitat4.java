import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;

public class MainActivitat4{
    public static void main(String[] args) throws IOException {
        System.out.println("ejercicio 1.5");
       SecretKey skey1;
        try {
            skey1 = UtilitatsXifrar.keygenKeyGeneration(128);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        String textxif = "Hola, em dic Aitor y estic encryptant y desencryptant text";

        byte[] txtencr = UtilitatsXifrar.encryptData(textxif.getBytes(),skey1);
        byte[] txtdecrypt = UtilitatsXifrar.decryptData(txtencr,skey1);
        String st = new String(txtdecrypt,0,txtdecrypt.length);
        System.out.println(st+"\n\n");


        System.out.println("ejercicio 1.6");
        SecretKey skey2 = UtilitatsXifrar.passwordKeyGeneration("1234asdf1234",128);
        byte[] txtencr2 = UtilitatsXifrar.encryptData(textxif.getBytes(),skey2);
        byte[] txtdecrypt2 = UtilitatsXifrar.decryptData(txtencr2,skey2);
        String st2 = new String(txtdecrypt2,0,txtdecrypt2.length);
        System.out.println(st2+"\n\n");

        System.out.println("ejercicio 1.7");
        String st3 = new String(skey2.getEncoded(),0,skey2.getEncoded().length);
        System.out.println(st3+"\n"+skey2.getAlgorithm()+"\n\n");

        System.out.println("ejercicio 1.8");
        SecretKey skey3 = UtilitatsXifrar.passwordKeyGeneration("12345678",128);
        byte[] txtdecrypt3 = UtilitatsXifrar.decryptData(txtencr2,skey3);
        String st4 = new String(txtdecrypt3,0,txtdecrypt3.length);
        System.out.println(st4+"\n\n");

        System.out.println("ejercicio 2.1");
        Path path = Paths.get("textamagat.crypt");
        byte[] textenbytes = Files.readAllBytes(path);

        File f = new File("clausA4.txt");
        FileReader fr = new FileReader(f);
        BufferedReader br = new BufferedReader(fr);
        String line = br.readLine();
        while(line != null ) {
            SecretKey sk1 = UtilitatsXifrar.passwordKeyGeneration(line,128);
            byte[] result = UtilitatsXifrar.decryptData(textenbytes,sk1);
            String string = new String(result,0,result.length);
            System.out.println("lectura: " + string);
            line = br.readLine();
        }

    }
}