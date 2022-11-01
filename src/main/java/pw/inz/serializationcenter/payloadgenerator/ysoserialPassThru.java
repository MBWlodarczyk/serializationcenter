package pw.inz.serializationcenter.payloadgenerator;

import org.springframework.beans.factory.annotation.Autowired;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;


public class ysoserialPassThru {

    @Autowired
    public ysoserialPassThru() {
        this.load();
    }

    private final String[] payloads = new String[]{"BeanShell1", "Click1", "Clojure", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2", "CommonsCollections3", "CommonsCollections4", "CommonsCollections5", "CommonsCollections6", "CommonsCollections7", "FileUpload1", "Groovy1", "Hibernate1", "Hibernate2", "JBossInterceptors1", "JRMPClient", "JRMPListener", "JSON1", "JavassistWeld1", "Jdk7u21", "Jython1", "MozillaRhino1", "MozillaRhino2", "Myfaces1", "Myfaces2", "ROME", "Spring1", "Spring2", "URLDNS", "Vaadin1", "Wicket1"};//todo from databse
    private final HashMap<String,byte[]> payloads_own = new HashMap<>();


    private boolean contains(String payloadname) {
        for (String payload : payloads) {
            if (payload.equals(payloadname)) return true;
        }
        return false;
    }
    public void load(){
        File folder = new File(System.getProperty("user.dir") + "\\libs\\payloads");
        for(File file : folder.listFiles()){
            try {
                payloads_own.put(file.getName(), Files.readAllBytes(Path.of(file.getPath())));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
    public String[] getPayloads(){
        this.load();
        ArrayList<String> payloads = new ArrayList<>(List.of(this.payloads));
        payloads.addAll(payloads_own.keySet());
        return payloads.toArray(new String[0]);
    }

    public byte[] save(String payloadname, String payloadcmd,String filename) {
        if (!contains(payloadname)) return null;

            Process proc;
            try {
                ProcessBuilder pb = new ProcessBuilder("java", "-jar", System.getProperty("user.dir") + "\\libs\\ysoserial-all.jar", payloadname, "\"" + payloadcmd + "\"");
                pb.redirectOutput(new File(System.getProperty("user.dir") + "\\libs\\" + filename));
                proc = pb.start();
                proc.waitFor(300, TimeUnit.MILLISECONDS);
                InputStream in = proc.getInputStream();
                byte[] c = new byte[in.available()];
                in.read(c, 0, c.length);

                InputStream err = proc.getErrorStream();
                byte[] a = new byte[err.available()];
                err.read(a, 0, a.length);
                return c;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }


    }
    public byte[] invoke(String payloadname, String payloadcmd) {
        if (contains(payloadname)) {

            Process proc;
            try {
                proc = new ProcessBuilder("java", "-jar", System.getProperty("user.dir") + "\\libs\\ysoserial-all.jar", payloadname, "\"" + payloadcmd + "\"").start();
                proc.waitFor(300, TimeUnit.MILLISECONDS);
                InputStream in = proc.getInputStream();
                byte[] c = new byte[in.available()];
                in.read(c, 0, c.length);

                InputStream err = proc.getErrorStream();
                byte[] a = new byte[err.available()];
                err.read(a, 0, a.length);
                System.out.println(new String(a));
                System.out.println(new String(c));
                return c;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        this.load();
        if(payloads_own.containsKey(payloadname)){
            return payloads_own.get(payloadname);
        }
        return null;
    }
}
