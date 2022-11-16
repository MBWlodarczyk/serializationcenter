package pw.inz.serializationcenter.classprobe;
import com.bishopfox.gadgetprobe.GadgetProbe;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.reactive.function.client.WebClient;
import org.thymeleaf.util.Validate;
import pw.inz.serializationcenter.webscanner.WebScanner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;

public class ClassProbe {

    private GadgetProbe gp;
    private final WebScanner ws;

    private String defaultDomain = "inz.elka.lol";

    private String defaultCallback = "http://20.160.206.145:8080/request_parsed.txt";



    @Autowired
    public ClassProbe() {
        this.gp = new GadgetProbe(defaultDomain);
        this.ws = new WebScanner();
    }

    public void swapDomain(String domain){
        gp = new GadgetProbe(domain);
    }


    public Object[] makeObj(String clazzesLong){
        String[] clazzes = clazzesLong.split("\r\n");
        Object[] result = new Object[clazzes.length];
        for (int i=0;i< clazzes.length;i++){
            result[i]=gp.getObject(clazzes[i]);
        }
        return result;
    }
    public String[] parseInput(String input){
        return null;
    }

    public String validate(){
        WebClient client = WebClient.create();

        WebClient.ResponseSpec responseSpec = client.get()
                .uri(defaultCallback)
                .retrieve();
        return responseSpec.bodyToMono(String.class).block();
    }


    public String send(String url, String request, String clazzesLong){
        Object[] payloads = makeObj(clazzesLong);

        for (Object payloadObj: payloads
             ) {
            try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
                 ObjectOutputStream oos = new ObjectOutputStream(bos)) {
                oos.writeObject(payloadObj);
                oos.flush();
                byte[] payload = bos.toByteArray();
                if(request.equals("")){ ws.sendBytePost(payload,url);}
                else if(request.startsWith("params[")){ws.sendPostParams(payload,url,request);}
                else {ws.sendPostRequest(payload,url,request);}
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return validate();
    }

    public String makeClassList(String gadgets) {
        return gadgets.replace("\\(.+;\\).+$","")
        .replace("INVOKE type gadget","")
        .replace("^(?:[\\t ]*(?:\\r?\\n|\\r))+","")
        .replace("\\/",".");
    }
}
